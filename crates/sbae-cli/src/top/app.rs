//! State management and pure domain transitions for the live metadata browser.

use std::collections::BTreeSet;
use std::time::Duration;

use sbae_proto::api::{SecretSummaryDto, VersionInfoDto};
use sbae_proto::{SecretPath, Tag};

/// Refresh interval in seconds domain newtype.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RefreshInterval(Duration);

impl RefreshInterval {
    #[must_use]
    pub fn from_secs(secs: u64) -> Self {
        Self(Duration::from_secs(secs.max(1)))
    }

    #[must_use]
    pub fn as_duration(&self) -> Duration {
        self.0
    }

    #[must_use]
    pub fn as_secs(&self) -> u64 {
        self.0.as_secs()
    }
}

/// Active path filter string domain newtype.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PathFilter(String);

impl PathFilter {
    #[must_use]
    pub fn new(filter: impl Into<String>) -> Self {
        Self(filter.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Sort column identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SortColumn {
    #[default]
    Path,
    Versions,
    Current,
    Tags,
    Updated,
}

impl SortColumn {
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::Path => "PATH",
            Self::Versions => "VERSIONS",
            Self::Current => "CURRENT",
            Self::Tags => "TAGS",
            Self::Updated => "UPDATED",
        }
    }

    #[must_use]
    pub fn next(&self) -> Self {
        match self {
            Self::Path => Self::Versions,
            Self::Versions => Self::Current,
            Self::Current => Self::Tags,
            Self::Tags => Self::Updated,
            Self::Updated => Self::Path,
        }
    }
}

/// Sort ordering direction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SortDirection {
    #[default]
    Ascending,
    Descending,
}

impl SortDirection {
    #[must_use]
    pub fn reverse(&self) -> Self {
        match self {
            Self::Ascending => Self::Descending,
            Self::Descending => Self::Ascending,
        }
    }

    #[must_use]
    pub fn indicator(&self) -> &'static str {
        match self {
            Self::Ascending => "▲",
            Self::Descending => "▼",
        }
    }
}

/// Composite sorting criteria.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct SortCriteria {
    pub column: SortColumn,
    pub direction: SortDirection,
}

impl SortCriteria {
    #[must_use]
    pub fn cycle_column(self) -> Self {
        Self {
            column: self.column.next(),
            direction: SortDirection::Ascending,
        }
    }

    #[must_use]
    pub fn toggle_direction(self) -> Self {
        Self {
            column: self.column,
            direction: self.direction.reverse(),
        }
    }
}

/// Interaction mode of the browser.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum AppMode {
    #[default]
    List,
    Detail,
    Filtering,
}

/// Status line notification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusMessage {
    pub text: String,
    pub is_error: bool,
}

/// In-memory state of the live metadata browser.
#[derive(Debug)]
pub struct App {
    all_secrets: Vec<SecretSummaryDto>,
    filtered_secrets: Vec<SecretSummaryDto>,
    selected_index: usize,
    selected_version_index: usize,
    path_filter: PathFilter,
    filter_input: String,
    saved_filter: String,
    selected_tag: Option<Tag>,
    sort_criteria: SortCriteria,
    mode: AppMode,
    paused: bool,
    status_message: Option<StatusMessage>,
    socket_path: String,
    last_refresh_time: Option<String>,
    versions_detail: Option<(SecretPath, Vec<VersionInfoDto>)>,
    versions_loading: bool,
}

impl App {
    #[must_use]
    pub fn new(socket_path: impl Into<String>) -> Self {
        Self {
            all_secrets: Vec::new(),
            filtered_secrets: Vec::new(),
            selected_index: 0,
            selected_version_index: 0,
            path_filter: PathFilter::default(),
            filter_input: String::new(),
            saved_filter: String::new(),
            selected_tag: None,
            sort_criteria: SortCriteria::default(),
            mode: AppMode::List,
            paused: false,
            status_message: None,
            socket_path: socket_path.into(),
            last_refresh_time: None,
            versions_detail: None,
            versions_loading: false,
        }
    }

    pub fn set_secrets(&mut self, secrets: Vec<SecretSummaryDto>) {
        self.all_secrets = secrets;
        self.recompute_filtered_and_sorted();
    }

    pub fn set_status_error(&mut self, error: impl Into<String>) {
        self.status_message = Some(StatusMessage {
            text: error.into(),
            is_error: true,
        });
    }

    pub fn set_status_info(&mut self, info: impl Into<String>) {
        self.status_message = Some(StatusMessage {
            text: info.into(),
            is_error: false,
        });
    }

    pub fn clear_status(&mut self) {
        self.status_message = None;
    }

    pub fn select_next(&mut self) {
        if self.filtered_secrets.is_empty() {
            self.selected_index = 0;
            return;
        }
        if self.selected_index + 1 < self.filtered_secrets.len() {
            self.selected_index += 1;
        }
    }

    pub fn select_prev(&mut self) {
        if self.filtered_secrets.is_empty() {
            self.selected_index = 0;
            return;
        }
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn select_first(&mut self) {
        self.selected_index = 0;
    }

    pub fn select_last(&mut self) {
        if self.filtered_secrets.is_empty() {
            self.selected_index = 0;
        } else {
            self.selected_index = self.filtered_secrets.len() - 1;
        }
    }

    pub fn select_page_down(&mut self, page_size: usize) {
        if self.filtered_secrets.is_empty() {
            self.selected_index = 0;
            return;
        }
        let max_idx = self.filtered_secrets.len() - 1;
        self.selected_index = (self.selected_index + page_size).min(max_idx);
    }

    pub fn select_page_up(&mut self, page_size: usize) {
        self.selected_index = self.selected_index.saturating_sub(page_size);
    }

    pub fn select_version_next(&mut self) {
        if let Some((_, ref versions)) = self.versions_detail {
            if !versions.is_empty() && self.selected_version_index + 1 < versions.len() {
                self.selected_version_index += 1;
            }
        }
    }

    pub fn select_version_prev(&mut self) {
        if self.selected_version_index > 0 {
            self.selected_version_index -= 1;
        }
    }

    pub fn start_filtering(&mut self) {
        self.mode = AppMode::Filtering;
        self.saved_filter = self.path_filter.0.clone();
        self.filter_input = self.path_filter.0.clone();
    }

    pub fn input_filter_char(&mut self, c: char) {
        self.filter_input.push(c);
        self.path_filter = PathFilter::new(self.filter_input.clone());
        self.recompute_filtered_and_sorted();
    }

    pub fn input_filter_backspace(&mut self) {
        self.filter_input.pop();
        self.path_filter = PathFilter::new(self.filter_input.clone());
        self.recompute_filtered_and_sorted();
    }

    pub fn apply_filter_input(&mut self) {
        self.path_filter = PathFilter::new(self.filter_input.clone());
        self.saved_filter.clear();
        self.mode = AppMode::List;
        self.recompute_filtered_and_sorted();
    }

    pub fn cancel_filter_input(&mut self) {
        self.path_filter = PathFilter::new(std::mem::take(&mut self.saved_filter));
        self.filter_input.clear();
        self.mode = AppMode::List;
        self.recompute_filtered_and_sorted();
    }

    pub fn apply_filter(&mut self, filter: impl Into<String>) {
        self.path_filter = PathFilter::new(filter);
        self.recompute_filtered_and_sorted();
    }

    pub fn clear_filter(&mut self) {
        self.path_filter = PathFilter::default();
        self.filter_input.clear();
        self.saved_filter.clear();
        self.recompute_filtered_and_sorted();
    }

    pub fn cycle_tag(&mut self) {
        let distinct = self.distinct_tags();
        if distinct.is_empty() {
            self.selected_tag = None;
            return;
        }

        self.selected_tag = match &self.selected_tag {
            None => Some(distinct[0].clone()),
            Some(current) => {
                if let Some(pos) = distinct.iter().position(|t| t == current) {
                    if pos + 1 < distinct.len() {
                        Some(distinct[pos + 1].clone())
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };
        self.recompute_filtered_and_sorted();
    }

    pub fn cycle_sort(&mut self) {
        self.sort_criteria = self.sort_criteria.cycle_column();
        self.recompute_filtered_and_sorted();
    }

    pub fn reverse_sort(&mut self) {
        self.sort_criteria = self.sort_criteria.toggle_direction();
        self.recompute_filtered_and_sorted();
    }

    pub fn toggle_pause(&mut self) {
        self.paused = !self.paused;
    }

    pub fn open_detail(&mut self) {
        self.mode = AppMode::Detail;
        self.selected_version_index = 0;
    }

    pub fn close_detail(&mut self) {
        self.mode = AppMode::List;
        self.versions_detail = None;
    }

    pub fn set_versions(&mut self, path: SecretPath, versions: Vec<VersionInfoDto>) {
        self.versions_detail = Some((path, versions));
        self.versions_loading = false;
        self.selected_version_index = 0;
    }

    pub fn set_versions_loading(&mut self, loading: bool) {
        self.versions_loading = loading;
    }

    pub fn set_last_refresh_time(&mut self, time: impl Into<String>) {
        self.last_refresh_time = Some(time.into());
    }

    #[must_use]
    pub fn distinct_tags(&self) -> Vec<Tag> {
        let mut set = BTreeSet::new();
        for secret in &self.all_secrets {
            for tag in &secret.tags {
                set.insert(tag.clone());
            }
        }
        set.into_iter().collect()
    }

    #[must_use]
    pub fn secrets(&self) -> &[SecretSummaryDto] {
        &self.all_secrets
    }

    #[must_use]
    pub fn filtered_secrets(&self) -> &[SecretSummaryDto] {
        &self.filtered_secrets
    }

    #[must_use]
    pub fn selected_index(&self) -> usize {
        self.selected_index
    }

    #[must_use]
    pub fn selected_version_index(&self) -> usize {
        self.selected_version_index
    }

    #[must_use]
    pub fn selected_secret(&self) -> Option<&SecretSummaryDto> {
        self.filtered_secrets.get(self.selected_index)
    }

    #[must_use]
    pub fn path_filter(&self) -> &PathFilter {
        &self.path_filter
    }

    #[must_use]
    pub fn filter_input(&self) -> &str {
        &self.filter_input
    }

    #[must_use]
    pub fn selected_tag(&self) -> Option<&Tag> {
        self.selected_tag.as_ref()
    }

    #[must_use]
    pub fn sort_criteria(&self) -> SortCriteria {
        self.sort_criteria
    }

    #[must_use]
    pub fn mode(&self) -> AppMode {
        self.mode
    }

    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    #[must_use]
    pub fn status_message(&self) -> Option<&StatusMessage> {
        self.status_message.as_ref()
    }

    #[must_use]
    pub fn socket_path(&self) -> &str {
        &self.socket_path
    }

    #[must_use]
    pub fn last_refresh_time(&self) -> Option<&str> {
        self.last_refresh_time.as_deref()
    }

    #[must_use]
    pub fn versions_detail(&self) -> Option<(&SecretPath, &[VersionInfoDto])> {
        self.versions_detail
            .as_ref()
            .map(|(p, v)| (p, v.as_slice()))
    }

    #[must_use]
    pub fn is_versions_loading(&self) -> bool {
        self.versions_loading
    }

    fn recompute_filtered_and_sorted(&mut self) {
        let mut list: Vec<SecretSummaryDto> = self
            .all_secrets
            .iter()
            .filter(|secret| {
                if !self.path_filter.is_empty() {
                    let needle = self.path_filter.as_str().to_lowercase();
                    if !secret.path.as_str().to_lowercase().contains(&needle) {
                        return false;
                    }
                }
                if let Some(ref tag) = self.selected_tag {
                    if !secret.tags.contains(tag) {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();

        list.sort_by(|a, b| {
            let ordering = match self.sort_criteria.column {
                SortColumn::Path => a.path.cmp(&b.path),
                SortColumn::Versions => a
                    .version_count
                    .cmp(&b.version_count)
                    .then_with(|| a.path.cmp(&b.path)),
                SortColumn::Current => a
                    .current_version
                    .cmp(&b.current_version)
                    .then_with(|| a.path.cmp(&b.path)),
                SortColumn::Tags => {
                    let tags_a = a
                        .tags
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    let tags_b = b
                        .tags
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(",");
                    tags_a.cmp(&tags_b).then_with(|| a.path.cmp(&b.path))
                }
                SortColumn::Updated => a
                    .updated_at
                    .cmp(&b.updated_at)
                    .then_with(|| a.path.cmp(&b.path)),
            };

            match self.sort_criteria.direction {
                SortDirection::Ascending => ordering,
                SortDirection::Descending => ordering.reverse(),
            }
        });

        self.filtered_secrets = list;

        if self.filtered_secrets.is_empty() {
            self.selected_index = 0;
        } else if self.selected_index >= self.filtered_secrets.len() {
            self.selected_index = self.filtered_secrets.len() - 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sbae_proto::Version;

    fn sample_secrets() -> Vec<SecretSummaryDto> {
        vec![
            SecretSummaryDto {
                path: SecretPath::new("prod/secret-a").unwrap(),
                current_version: Some(Version::new(2).unwrap()),
                version_count: 2,
                tags: vec![Tag::new("env", "prod").unwrap()],
                updated_at: "2026-01-02T00:00:00Z".to_owned(),
            },
            SecretSummaryDto {
                path: SecretPath::new("dev/secret-b").unwrap(),
                current_version: Some(Version::new(1).unwrap()),
                version_count: 1,
                tags: vec![Tag::new("env", "dev").unwrap()],
                updated_at: "2026-01-01T00:00:00Z".to_owned(),
            },
            SecretSummaryDto {
                path: SecretPath::new("prod/secret-c").unwrap(),
                current_version: Some(Version::new(4).unwrap()),
                version_count: 5,
                tags: vec![
                    Tag::new("env", "prod").unwrap(),
                    Tag::new("tier", "backend").unwrap(),
                ],
                updated_at: "2026-01-03T00:00:00Z".to_owned(),
            },
        ]
    }

    #[test]
    fn selection_stays_in_bounds_at_both_ends_and_across_an_empty_list() {
        let mut app = App::new("/run/secretbae/sock");

        assert_eq!(app.selected_index(), 0);
        assert!(app.selected_secret().is_none());
        app.select_next();
        assert_eq!(app.selected_index(), 0);
        app.select_prev();
        assert_eq!(app.selected_index(), 0);
        app.select_first();
        assert_eq!(app.selected_index(), 0);
        app.select_last();
        assert_eq!(app.selected_index(), 0);
        app.select_page_down(10);
        assert_eq!(app.selected_index(), 0);
        app.select_page_up(10);
        assert_eq!(app.selected_index(), 0);

        app.set_secrets(sample_secrets());
        assert_eq!(app.filtered_secrets().len(), 3);
        assert_eq!(app.selected_index(), 0);

        app.select_prev();
        assert_eq!(app.selected_index(), 0);

        app.select_next();
        assert_eq!(app.selected_index(), 1);
        app.select_next();
        assert_eq!(app.selected_index(), 2);

        app.select_next();
        assert_eq!(app.selected_index(), 2);

        app.select_first();
        assert_eq!(app.selected_index(), 0);
        app.select_page_down(100);
        assert_eq!(app.selected_index(), 2);

        app.select_page_up(100);
        assert_eq!(app.selected_index(), 0);

        app.select_last();
        assert_eq!(app.selected_index(), 2);
        app.apply_filter("secret-c");
        assert_eq!(app.filtered_secrets().len(), 1);
        assert_eq!(app.selected_index(), 0);
    }

    #[test]
    fn path_filter_narrows_rows_and_clearing_it_restores_them() {
        let mut app = App::new("/run/secretbae/sock");
        app.set_secrets(sample_secrets());
        assert_eq!(app.filtered_secrets().len(), 3);

        app.apply_filter("secret-a");
        assert_eq!(app.filtered_secrets().len(), 1);
        assert_eq!(app.filtered_secrets()[0].path.as_str(), "prod/secret-a");

        app.apply_filter("nonexistent");
        assert_eq!(app.filtered_secrets().len(), 0);

        app.clear_filter();
        assert_eq!(app.filtered_secrets().len(), 3);
    }

    #[test]
    fn cycling_tags_visits_every_distinct_tag_then_returns_to_unfiltered() {
        let mut app = App::new("/run/secretbae/sock");
        app.set_secrets(sample_secrets());

        assert_eq!(app.selected_tag(), None);
        assert_eq!(app.filtered_secrets().len(), 3);

        app.cycle_tag();
        assert_eq!(
            app.selected_tag().map(ToString::to_string).as_deref(),
            Some("env=dev")
        );
        assert_eq!(app.filtered_secrets().len(), 1);

        app.cycle_tag();
        assert_eq!(
            app.selected_tag().map(ToString::to_string).as_deref(),
            Some("env=prod")
        );
        assert_eq!(app.filtered_secrets().len(), 2);

        app.cycle_tag();
        assert_eq!(
            app.selected_tag().map(ToString::to_string).as_deref(),
            Some("tier=backend")
        );
        assert_eq!(app.filtered_secrets().len(), 1);

        app.cycle_tag();
        assert_eq!(app.selected_tag(), None);
        assert_eq!(app.filtered_secrets().len(), 3);
    }

    // Table-driven over every column and both directions; splitting it loses the exhaustive check.
    #[test]
    #[allow(clippy::too_many_lines)]
    fn sorting_by_each_column_orders_correctly_and_reversing_inverts_it() {
        let mut app = App::new("/run/secretbae/sock");
        app.set_secrets(sample_secrets());

        // 1. Path sort
        assert_eq!(app.sort_criteria().column, SortColumn::Path);
        assert_eq!(app.sort_criteria().direction, SortDirection::Ascending);
        let paths: Vec<&str> = app
            .filtered_secrets()
            .iter()
            .map(|s| s.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec!["dev/secret-b", "prod/secret-a", "prod/secret-c"]
        );

        app.reverse_sort();
        assert_eq!(app.sort_criteria().direction, SortDirection::Descending);
        let paths: Vec<&str> = app
            .filtered_secrets()
            .iter()
            .map(|s| s.path.as_str())
            .collect();
        assert_eq!(
            paths,
            vec!["prod/secret-c", "prod/secret-a", "dev/secret-b"]
        );

        // 2. Versions sort (version_count)
        app.cycle_sort();
        assert_eq!(app.sort_criteria().column, SortColumn::Versions);
        let versions: Vec<u64> = app
            .filtered_secrets()
            .iter()
            .map(|s| s.version_count)
            .collect();
        assert_eq!(versions, vec![1, 2, 5]);

        app.reverse_sort();
        let versions: Vec<u64> = app
            .filtered_secrets()
            .iter()
            .map(|s| s.version_count)
            .collect();
        assert_eq!(versions, vec![5, 2, 1]);

        // 3. Current version sort
        app.cycle_sort();
        assert_eq!(app.sort_criteria().column, SortColumn::Current);
        let currents: Vec<Option<u32>> = app
            .filtered_secrets()
            .iter()
            .map(|s| s.current_version.map(Version::get))
            .collect();
        assert_eq!(currents, vec![Some(1), Some(2), Some(4)]);

        app.reverse_sort();
        let currents: Vec<Option<u32>> = app
            .filtered_secrets()
            .iter()
            .map(|s| s.current_version.map(Version::get))
            .collect();
        assert_eq!(currents, vec![Some(4), Some(2), Some(1)]);

        // 4. Tags sort
        app.cycle_sort();
        assert_eq!(app.sort_criteria().column, SortColumn::Tags);
        let tags: Vec<String> = app
            .filtered_secrets()
            .iter()
            .map(|s| {
                s.tags
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect();
        assert_eq!(tags, vec!["env=dev", "env=prod", "env=prod,tier=backend"]);

        app.reverse_sort();
        let tags: Vec<String> = app
            .filtered_secrets()
            .iter()
            .map(|s| {
                s.tags
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect();
        assert_eq!(tags, vec!["env=prod,tier=backend", "env=prod", "env=dev"]);

        // 5. Updated sort
        app.cycle_sort();
        assert_eq!(app.sort_criteria().column, SortColumn::Updated);
        let updated: Vec<&str> = app
            .filtered_secrets()
            .iter()
            .map(|s| s.updated_at.as_str())
            .collect();
        assert_eq!(
            updated,
            vec![
                "2026-01-01T00:00:00Z",
                "2026-01-02T00:00:00Z",
                "2026-01-03T00:00:00Z"
            ]
        );

        app.reverse_sort();
        let updated: Vec<&str> = app
            .filtered_secrets()
            .iter()
            .map(|s| s.updated_at.as_str())
            .collect();
        assert_eq!(
            updated,
            vec![
                "2026-01-03T00:00:00Z",
                "2026-01-02T00:00:00Z",
                "2026-01-01T00:00:00Z"
            ]
        );
    }

    #[test]
    fn filtering_then_sorting_composes_without_replacing_each_other() {
        let mut app = App::new("/run/secretbae/sock");
        app.set_secrets(sample_secrets());

        app.apply_filter("prod");
        assert_eq!(app.filtered_secrets().len(), 2);

        app.cycle_sort();
        app.reverse_sort();

        assert_eq!(app.filtered_secrets().len(), 2);
        assert_eq!(app.filtered_secrets()[0].path.as_str(), "prod/secret-c");
        assert_eq!(app.filtered_secrets()[0].version_count, 5);
        assert_eq!(app.filtered_secrets()[1].path.as_str(), "prod/secret-a");
        assert_eq!(app.filtered_secrets()[1].version_count, 2);

        app.cycle_tag();
        assert_eq!(app.filtered_secrets().len(), 0);

        app.cycle_tag();
        assert_eq!(app.filtered_secrets().len(), 2);
        assert_eq!(app.filtered_secrets()[0].path.as_str(), "prod/secret-c");
        assert_eq!(app.filtered_secrets()[1].path.as_str(), "prod/secret-a");
    }

    #[test]
    fn request_failure_surfaces_as_status_message_and_leaves_prior_rows_intact() {
        let mut app = App::new("/run/secretbae/sock");
        app.set_secrets(sample_secrets());
        assert_eq!(app.filtered_secrets().len(), 3);
        assert_eq!(app.status_message(), None);

        let err_msg =
            "failed to connect to daemon socket '/run/secretbae/sock': Connection refused";
        app.set_status_error(err_msg);

        assert_eq!(
            app.status_message(),
            Some(&StatusMessage {
                text: err_msg.to_owned(),
                is_error: true,
            })
        );

        assert_eq!(app.filtered_secrets().len(), 3);
        assert_eq!(app.filtered_secrets()[0].path.as_str(), "dev/secret-b");
        assert_eq!(app.filtered_secrets()[1].path.as_str(), "prod/secret-a");
        assert_eq!(app.filtered_secrets()[2].path.as_str(), "prod/secret-c");
    }

    #[test]
    fn top_module_references_neither_read_nor_resolve_route_constant() {
        let mod_src = include_str!("mod.rs");
        let app_src = include_str!("app.rs");
        let render_src = include_str!("render.rs");

        let read_route_kw = format!("{}:{}", "route", "READ");
        let resolve_route_kw = format!("{}:{}", "route", "RESOLVE");
        let read_endpoint = format!("/v1/secrets/{}", "read");
        let resolve_endpoint = format!("/v1/{}", "resolve");
        let read_req_type = format!("{}Request", "Read");
        let read_resp_type = format!("{}Response", "Read");
        let resolve_req_type = format!("{}Request", "Resolve");
        let resolve_resp_type = format!("{}Response", "Resolve");

        let sources = [("mod.rs", mod_src), ("render.rs", render_src)];
        for (name, content) in sources {
            assert!(
                !content.contains(&read_route_kw),
                "{name} references {read_route_kw}"
            );
            assert!(
                !content.contains(&resolve_route_kw),
                "{name} references {resolve_route_kw}"
            );
            assert!(
                !content.contains(&read_endpoint),
                "{name} references {read_endpoint}"
            );
            assert!(
                !content.contains(&resolve_endpoint),
                "{name} references {resolve_endpoint}"
            );
            assert!(
                !content.contains(&read_req_type),
                "{name} references {read_req_type}"
            );
            assert!(
                !content.contains(&read_resp_type),
                "{name} references {read_resp_type}"
            );
            assert!(
                !content.contains(&resolve_req_type),
                "{name} references {resolve_req_type}"
            );
            assert!(
                !content.contains(&resolve_resp_type),
                "{name} references {resolve_resp_type}"
            );
        }

        let app_code = app_src.split("#[cfg(test)]").next().unwrap();
        assert!(
            !app_code.contains(&read_route_kw),
            "app.rs references {read_route_kw}"
        );
        assert!(
            !app_code.contains(&resolve_route_kw),
            "app.rs references {resolve_route_kw}"
        );
        assert!(
            !app_code.contains(&read_endpoint),
            "app.rs references {read_endpoint}"
        );
        assert!(
            !app_code.contains(&resolve_endpoint),
            "app.rs references {resolve_endpoint}"
        );
        assert!(
            !app_code.contains(&read_req_type),
            "app.rs references {read_req_type}"
        );
        assert!(
            !app_code.contains(&read_resp_type),
            "app.rs references {read_resp_type}"
        );
        assert!(
            !app_code.contains(&resolve_req_type),
            "app.rs references {resolve_req_type}"
        );
        assert!(
            !app_code.contains(&resolve_resp_type),
            "app.rs references {resolve_resp_type}"
        );
    }

    #[test]
    fn incremental_filter_input_flow_updates_and_cancels_correctly() {
        let mut app = App::new("/run/secretbae/sock");
        app.set_secrets(sample_secrets());

        app.start_filtering();
        assert_eq!(app.mode(), AppMode::Filtering);

        app.input_filter_char('d');
        app.input_filter_char('e');
        app.input_filter_char('v');
        assert_eq!(app.filter_input(), "dev");
        assert_eq!(app.filtered_secrets().len(), 1);

        app.input_filter_backspace();
        assert_eq!(app.filter_input(), "de");
        assert_eq!(app.filtered_secrets().len(), 1);

        app.cancel_filter_input();
        assert_eq!(app.mode(), AppMode::List);
        assert_eq!(app.filtered_secrets().len(), 3);
    }
}
