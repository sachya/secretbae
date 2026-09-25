//! Colour palette and the small formatting helpers the table cells are built from.
//!
//! Kept apart from layout so the look can be retuned in one place, and so the rules that
//! carry meaning -- production tags reading as louder than development ones, a destroyed
//! version reading as gone -- are stated once rather than scattered through the renderer.

use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use sbae_proto::{Tag, VersionState};

pub const BASE: Color = Color::Rgb(20, 23, 33);
pub const PANEL: Color = Color::Rgb(28, 32, 45);
/// Every other row, so long rows stay easy to track across the width.
pub const ZEBRA: Color = Color::Rgb(24, 27, 38);
pub const SELECTED: Color = Color::Rgb(54, 74, 128);

pub const TEXT: Color = Color::Rgb(224, 229, 242);
pub const MUTED: Color = Color::Rgb(124, 133, 158);
pub const BORDER: Color = Color::Rgb(58, 66, 92);

pub const ACCENT: Color = Color::Rgb(122, 220, 255);
pub const ACCENT_ALT: Color = Color::Rgb(199, 146, 255);
pub const OK: Color = Color::Rgb(126, 231, 135);
pub const WARN: Color = Color::Rgb(250, 208, 122);
pub const DANGER: Color = Color::Rgb(255, 121, 121);

/// Colours for tags that carry no special meaning, chosen by a stable hash of the tag key so
/// `app=billing` keeps the same colour between refreshes and between runs.
const CHIP_PALETTE: [Color; 5] = [
    Color::Rgb(129, 200, 255),
    Color::Rgb(199, 146, 255),
    Color::Rgb(255, 175, 214),
    Color::Rgb(126, 231, 135),
    Color::Rgb(255, 199, 119),
];

#[must_use]
pub fn title_bar() -> Style {
    Style::default().bg(Color::Rgb(38, 48, 74)).fg(TEXT)
}

#[must_use]
pub fn header_cell() -> Style {
    Style::default()
        .bg(Color::Rgb(38, 44, 62))
        .fg(ACCENT)
        .add_modifier(Modifier::BOLD)
}

#[must_use]
pub fn row_background(index: usize) -> Style {
    Style::default()
        .bg(if index % 2 == 0 { PANEL } else { ZEBRA })
        .fg(TEXT)
}

#[must_use]
pub fn selected_row() -> Style {
    Style::default()
        .bg(SELECTED)
        .fg(Color::White)
        .add_modifier(Modifier::BOLD)
}

/// A key hint rendered as a inverse-video chip, so the bindings read as pressable keys
/// rather than as prose.
#[must_use]
pub fn key_chip(key: &str, label: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(
            format!(" {key} "),
            Style::default()
                .bg(ACCENT)
                .fg(BASE)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {label}  "), Style::default().fg(MUTED)),
    ]
}

/// Environment tags are colour-coded by severity: production has to be the one that catches
/// the eye when an operator is scanning for what they are about to change.
#[must_use]
pub fn tag_colour(tag: &Tag) -> Color {
    if tag.key() == "env" {
        return match tag.value() {
            "prod" | "production" | "live" => DANGER,
            "staging" | "stage" | "preprod" | "uat" => WARN,
            "dev" | "development" | "local" | "test" => OK,
            _ => ACCENT,
        };
    }

    let hash: usize = tag.key().bytes().map(usize::from).sum();
    CHIP_PALETTE[hash % CHIP_PALETTE.len()]
}

/// Tags render as inverse-video chips so they read as labels attached to the row rather than
/// as more of the row's text, which matters when a key carries several of them.
#[must_use]
pub fn tag_chip(tag: &Tag) -> Span<'static> {
    Span::styled(
        format!(" {tag} "),
        Style::default()
            .fg(BASE)
            .bg(tag_colour(tag))
            .add_modifier(Modifier::BOLD),
    )
}

#[must_use]
pub fn version_state_style(state: VersionState) -> (&'static str, Color) {
    match state {
        VersionState::Active => ("● active", OK),
        VersionState::Deleted => ("◐ deleted", WARN),
        VersionState::Destroyed => ("○ destroyed", DANGER),
    }
}

/// A count plus a short bar, so relative depth is readable without comparing digits.
///
/// The bar saturates rather than growing without bound -- past a handful of versions the
/// exact number matters more than the shape.
#[must_use]
pub fn version_gauge(count: u64) -> Vec<Span<'static>> {
    const MAX_BLOCKS: u64 = 6;

    let colour = match count {
        0 => MUTED,
        1 => ACCENT,
        2..=4 => OK,
        5..=9 => WARN,
        _ => ACCENT_ALT,
    };

    let filled = count.min(MAX_BLOCKS);
    let mut bar = "▮".repeat(usize::try_from(filled).unwrap_or(0));
    if count > MAX_BLOCKS {
        bar.push('+');
    }

    vec![
        Span::styled(
            format!("{count:>3} "),
            Style::default().fg(colour).add_modifier(Modifier::BOLD),
        ),
        Span::styled(bar, Style::default().fg(colour)),
    ]
}

/// Split a path so the parent reads as context and the leaf as the name.
#[must_use]
pub fn path_spans(path: &str, selected: bool) -> Vec<Span<'static>> {
    let leaf_style = if selected {
        Style::default()
            .fg(Color::White)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(TEXT).add_modifier(Modifier::BOLD)
    };

    match path.rsplit_once('/') {
        Some((parent, leaf)) => vec![
            Span::styled(format!("{parent}/"), Style::default().fg(MUTED)),
            Span::styled(leaf.to_owned(), leaf_style),
        ],
        None => vec![Span::styled(path.to_owned(), leaf_style)],
    }
}

/// Compact age, in the spirit of `top`: an operator scanning the list wants "how long ago",
/// not a timestamp they have to subtract in their head.
#[must_use]
pub fn relative_age(rfc3339: &str) -> Span<'static> {
    let Ok(then) =
        time::OffsetDateTime::parse(rfc3339, &time::format_description::well_known::Rfc3339)
    else {
        return Span::styled(rfc3339.to_owned(), Style::default().fg(MUTED));
    };

    let seconds = (time::OffsetDateTime::now_utc() - then)
        .whole_seconds()
        .max(0);
    let (text, colour) = match seconds {
        0..=59 => (format!("{seconds}s ago"), OK),
        60..=3599 => (format!("{}m ago", seconds / 60), OK),
        3600..=86_399 => (format!("{}h ago", seconds / 3600), TEXT),
        _ => (format!("{}d ago", seconds / 86_400), MUTED),
    };

    Span::styled(text, Style::default().fg(colour))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_tags_are_louder_than_development_ones() {
        let prod: Tag = "env=prod".parse().unwrap();
        let dev: Tag = "env=dev".parse().unwrap();
        assert_eq!(tag_colour(&prod), DANGER);
        assert_eq!(tag_colour(&dev), OK);
        assert_ne!(tag_colour(&prod), tag_colour(&dev));
    }

    #[test]
    fn a_tag_keeps_the_same_colour_between_renders() {
        let tag: Tag = "app=billing".parse().unwrap();
        assert_eq!(tag_colour(&tag), tag_colour(&tag));
    }

    #[test]
    fn the_version_gauge_saturates_rather_than_growing_without_bound() {
        let wide = version_gauge(400);
        let bar: String = wide[1].content.to_string();
        assert!(
            bar.ends_with('+'),
            "a large count must be marked as saturated"
        );
        assert!(
            bar.chars().count() <= 8,
            "the bar must not overflow its column: {bar}"
        );
    }

    #[test]
    fn the_gauge_reports_the_exact_count_alongside_the_bar() {
        assert!(version_gauge(3)[0].content.contains('3'));
        assert_eq!(version_gauge(3)[1].content.chars().count(), 3);
    }

    #[test]
    fn a_path_is_split_into_dimmed_parent_and_bold_leaf() {
        let spans = path_spans("prod/billing/db_url", false);
        assert_eq!(spans[0].content, "prod/billing/");
        assert_eq!(spans[1].content, "db_url");

        let single = path_spans("solo", false);
        assert_eq!(single.len(), 1);
        assert_eq!(single[0].content, "solo");
    }

    #[test]
    fn ages_render_in_the_largest_unit_that_fits() {
        let now = time::OffsetDateTime::now_utc();
        let format = &time::format_description::well_known::Rfc3339;

        let render = |ago: time::Duration| {
            relative_age(&(now - ago).format(format).unwrap())
                .content
                .to_string()
        };

        assert!(render(time::Duration::seconds(5)).ends_with("s ago"));
        assert!(render(time::Duration::minutes(5)).starts_with('5'));
        assert!(render(time::Duration::hours(5)).ends_with("h ago"));
        assert!(render(time::Duration::days(5)).ends_with("d ago"));
    }

    /// An unparseable timestamp must still render something rather than blanking the column.
    #[test]
    fn an_unparseable_timestamp_falls_back_to_the_raw_value() {
        assert_eq!(relative_age("not-a-timestamp").content, "not-a-timestamp");
    }

    #[test]
    fn every_version_state_has_a_distinct_marker_and_colour() {
        let states = [
            VersionState::Active,
            VersionState::Deleted,
            VersionState::Destroyed,
        ]
        .map(version_state_style);

        assert_eq!(states[0].1, OK);
        assert_eq!(states[2].1, DANGER);
        assert_ne!(states[0].0, states[1].0);
        assert_ne!(states[1].0, states[2].0);
    }
}
