//! Drawing the `top` view.
//!
//! Reads `App` and writes to the frame; it holds no state of its own, so every behaviour is
//! decided and tested in `app.rs` rather than here.

use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, Cell, Paragraph, Row, Table, TableState};
use ratatui::Frame;

use crate::top::app::{App, AppMode, SortColumn};
use crate::top::theme;

pub fn render(app: &App, frame: &mut Frame) {
    let area = frame.area();
    frame.render_widget(
        Block::default().style(Style::default().bg(theme::BASE)),
        area,
    );

    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(6),
            Constraint::Length(1),
        ])
        .split(area);

    render_title(app, frame, panes[0]);
    render_chips(app, frame, panes[1]);
    render_body(app, frame, panes[2]);
    render_footer(app, frame, panes[3]);
}

/// A filled bar with the product mark on the left and the clock on the right.
fn render_title(app: &App, frame: &mut Frame, area: Rect) {
    let left = vec![
        Span::styled(
            " ▍SECRETBAE ",
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "top ",
            Style::default()
                .fg(theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("· live metadata", Style::default().fg(theme::MUTED)),
    ];

    let right = vec![
        Span::styled(
            if app.is_paused() {
                " ⏸ PAUSED "
            } else {
                " ● LIVE "
            },
            Style::default()
                .fg(if app.is_paused() {
                    theme::WARN
                } else {
                    theme::OK
                })
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{} ", app.last_refresh_time().unwrap_or("—")),
            Style::default().fg(theme::TEXT),
        ),
    ];

    frame.render_widget(
        Paragraph::new(justified(area.width, left, right)).style(theme::title_bar()),
        area,
    );
}

/// The status chips: where we are connected, how much is in view, and what is filtering it.
fn render_chips(app: &App, frame: &mut Frame, area: Rect) {
    let shown = app.filtered_secrets().len();
    let total = app.secrets().len();
    let versions: u64 = app
        .filtered_secrets()
        .iter()
        .map(|secret| secret.version_count)
        .sum();

    let mut spans = Vec::new();
    spans.extend(chip("socket", app.socket_path(), theme::ACCENT_ALT));
    spans.extend(chip("keys", &format!("{shown}/{total}"), theme::OK));
    spans.extend(chip("versions", &versions.to_string(), theme::ACCENT));

    if !app.path_filter().is_empty() {
        spans.extend(chip("path", app.path_filter().as_str(), theme::WARN));
    }
    if let Some(tag) = app.selected_tag() {
        spans.extend(chip("tag", &tag.to_string(), theme::tag_colour(tag)));
    }
    spans.pop();

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn chip(label: &str, value: &str, colour: ratatui::style::Color) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!(" {label} "), Style::default().fg(theme::MUTED)),
        Span::styled(
            value.to_owned(),
            Style::default().fg(colour).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │", Style::default().fg(theme::BORDER)),
    ]
}

fn render_body(app: &App, frame: &mut Frame, area: Rect) {
    match app.mode() {
        AppMode::Detail => {
            let split = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
                .split(area);
            render_secrets(app, frame, split[0]);
            render_versions(app, frame, split[1]);
        }
        AppMode::List | AppMode::Filtering => render_secrets(app, frame, area),
    }
}

fn panel(title: Line<'static>) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::BORDER))
        .title(title)
        .title_alignment(Alignment::Left)
}

// One cohesive layout pass over the table; splitting it up would scatter widget state.
#[allow(clippy::too_many_lines)]
fn render_secrets(app: &App, frame: &mut Frame, area: Rect) {
    let criteria = app.sort_criteria();
    let heading = |column: SortColumn, text: &str| {
        let sorted = criteria.column == column;
        let label = if sorted {
            format!("{text} {}", criteria.direction.indicator())
        } else {
            text.to_owned()
        };
        Cell::from(Span::styled(
            label,
            if sorted {
                Style::default()
                    .fg(theme::WARN)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD)
            },
        ))
    };

    let header = Row::new(vec![
        heading(SortColumn::Path, "KEY"),
        heading(SortColumn::Versions, "VERSIONS"),
        heading(SortColumn::Current, "CURRENT"),
        heading(SortColumn::Tags, "TAGS"),
        heading(SortColumn::Updated, "UPDATED"),
    ])
    .style(theme::header_cell())
    .height(1);

    let selected = app.selected_index();
    let rows: Vec<Row<'static>> = if app.filtered_secrets().is_empty() {
        vec![Row::new(vec![Cell::from(Span::styled(
            if app.secrets().is_empty() {
                "  no secrets in this store yet — try: secretbae put prod/app/key --value ..."
            } else {
                "  nothing matches the current filter — press / to change it, or t to clear the tag"
            },
            Style::default()
                .fg(theme::MUTED)
                .add_modifier(Modifier::ITALIC),
        ))])]
    } else {
        app.filtered_secrets()
            .iter()
            .enumerate()
            .map(|(index, secret)| {
                let is_selected = index == selected;
                let current = secret
                    .current_version
                    .map_or_else(|| "—".to_owned(), |version| format!("v{version}"));

                let mut tags: Vec<Span<'static>> = Vec::new();
                for tag in &secret.tags {
                    if !tags.is_empty() {
                        tags.push(Span::raw(" "));
                    }
                    tags.push(theme::tag_chip(tag));
                }
                if tags.is_empty() {
                    tags.push(Span::styled("—", Style::default().fg(theme::MUTED)));
                }

                Row::new(vec![
                    Cell::from(Line::from(theme::path_spans(
                        secret.path.as_str(),
                        is_selected,
                    ))),
                    Cell::from(Line::from(theme::version_gauge(secret.version_count))),
                    Cell::from(Span::styled(
                        current,
                        Style::default()
                            .fg(theme::ACCENT)
                            .add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(Line::from(tags)),
                    Cell::from(Line::from(theme::relative_age(&secret.updated_at))),
                ])
                .style(theme::row_background(index))
            })
            .collect()
    };

    let title = Line::from(vec![
        Span::styled("─ ", Style::default().fg(theme::BORDER)),
        Span::styled(
            "KEYS",
            Style::default()
                .fg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(" {} ", app.filtered_secrets().len()),
            Style::default()
                .fg(theme::BASE)
                .bg(theme::ACCENT)
                .add_modifier(Modifier::BOLD),
        ),
    ]);

    let table = Table::new(
        rows,
        [
            Constraint::Min(26),
            Constraint::Length(11),
            Constraint::Length(8),
            Constraint::Percentage(34),
            Constraint::Length(12),
        ],
    )
    .header(header)
    .block(panel(title))
    .column_spacing(2)
    .row_highlight_style(theme::selected_row())
    .highlight_symbol(Span::styled(
        "▶ ",
        Style::default()
            .fg(theme::ACCENT)
            .add_modifier(Modifier::BOLD),
    ));

    let mut state = TableState::default();
    if !app.filtered_secrets().is_empty() {
        state.select(Some(selected));
    }
    frame.render_stateful_widget(table, area, &mut state);
}

fn render_versions(app: &App, frame: &mut Frame, area: Rect) {
    let Some((path, versions)) = app.versions_detail() else {
        let message = if app.is_versions_loading() {
            "loading versions…"
        } else {
            "no versions"
        };
        frame.render_widget(
            Paragraph::new(Span::styled(message, Style::default().fg(theme::MUTED))).block(panel(
                Line::from(Span::styled(
                    "─ VERSIONS",
                    Style::default()
                        .fg(theme::ACCENT_ALT)
                        .add_modifier(Modifier::BOLD),
                )),
            )),
            area,
        );
        return;
    };

    let header = Row::new(
        ["VERSION", "STATE", "CREATED", "BY", "COMMENT"].map(|text| {
            Cell::from(Span::styled(
                text,
                Style::default().add_modifier(Modifier::BOLD),
            ))
        }),
    )
    .style(theme::header_cell())
    .height(1);

    let rows: Vec<Row<'static>> = versions
        .iter()
        .enumerate()
        .map(|(index, info)| {
            let (marker, colour) = theme::version_state_style(info.state);
            Row::new(vec![
                Cell::from(Span::styled(
                    format!("v{}", info.version),
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                )),
                Cell::from(Span::styled(
                    marker,
                    Style::default().fg(colour).add_modifier(Modifier::BOLD),
                )),
                Cell::from(Line::from(theme::relative_age(&info.created_at))),
                Cell::from(Span::styled(
                    info.created_by.clone().unwrap_or_else(|| "—".to_owned()),
                    Style::default().fg(theme::MUTED),
                )),
                Cell::from(Span::styled(
                    info.comment.clone().unwrap_or_else(|| "—".to_owned()),
                    Style::default().fg(theme::TEXT),
                )),
            ])
            .style(theme::row_background(index))
        })
        .collect();

    let title = Line::from(vec![
        Span::styled("─ ", Style::default().fg(theme::BORDER)),
        Span::styled(
            "VERSIONS ",
            Style::default()
                .fg(theme::ACCENT_ALT)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(path.to_string(), Style::default().fg(theme::TEXT)),
    ]);

    let table = Table::new(
        rows,
        [
            Constraint::Length(9),
            Constraint::Length(13),
            Constraint::Length(12),
            Constraint::Length(14),
            Constraint::Min(10),
        ],
    )
    .header(header)
    .block(panel(title))
    .column_spacing(2)
    .row_highlight_style(theme::selected_row())
    .highlight_symbol(Span::styled("▶ ", Style::default().fg(theme::ACCENT_ALT)));

    let mut state = TableState::default();
    if !versions.is_empty() {
        state.select(Some(app.selected_version_index()));
    }
    frame.render_stateful_widget(table, area, &mut state);
}

/// Key hints, or whatever the last action had to say -- a status message displaces the hints
/// rather than competing with them for the same line.
fn render_footer(app: &App, frame: &mut Frame, area: Rect) {
    if let Some(status) = app.status_message() {
        let (marker, colour) = if status.is_error {
            (" ✖ ", theme::DANGER)
        } else {
            (" ✔ ", theme::OK)
        };

        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled(
                    marker,
                    Style::default()
                        .bg(colour)
                        .fg(theme::BASE)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(" {}", status.text), Style::default().fg(colour)),
            ])),
            area,
        );
        return;
    }

    let hints: Vec<(&str, &str)> = match app.mode() {
        AppMode::Filtering => vec![("type", "filter"), ("↵", "apply"), ("esc", "cancel")],
        AppMode::Detail => vec![
            ("↑↓", "version"),
            ("esc", "back"),
            ("r", "refresh"),
            ("q", "quit"),
        ],
        AppMode::List => vec![
            ("↑↓", "move"),
            ("↵", "versions"),
            ("/", "filter"),
            ("t", "tag"),
            ("s", "sort"),
            ("p", "pause"),
            ("q", "quit"),
        ],
    };

    let mut spans = Vec::new();
    if app.mode() == AppMode::Filtering {
        spans.push(Span::styled(
            format!(" /{}▏", app.filter_input()),
            Style::default()
                .fg(theme::WARN)
                .add_modifier(Modifier::BOLD),
        ));
    }
    for (key, label) in hints {
        spans.extend(theme::key_chip(key, label));
    }

    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Lay `left` against the start of the line and `right` against its end.
fn justified(width: u16, left: Vec<Span<'static>>, right: Vec<Span<'static>>) -> Line<'static> {
    let used: usize = left
        .iter()
        .chain(right.iter())
        .map(|span| span.content.chars().count())
        .sum();
    let padding = usize::from(width).saturating_sub(used);

    let mut spans = left;
    spans.push(Span::raw(" ".repeat(padding)));
    spans.extend(right);
    Line::from(spans)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_justified_line_fills_exactly_the_available_width() {
        let line = justified(40, vec![Span::raw("left")], vec![Span::raw("right")]);
        let rendered: String = line
            .spans
            .iter()
            .map(|span| span.content.as_ref())
            .collect();

        assert_eq!(rendered.chars().count(), 40);
        assert!(rendered.starts_with("left"));
        assert!(rendered.ends_with("right"));
    }

    /// A narrow terminal must not panic on the subtraction that computes the padding.
    #[test]
    fn justification_survives_a_width_smaller_than_its_content() {
        let line = justified(
            3,
            vec![Span::raw("a long left side")],
            vec![Span::raw("and right")],
        );
        assert!(!line.spans.is_empty());
    }
}
