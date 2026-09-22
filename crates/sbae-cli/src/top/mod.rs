//! Top-style interactive terminal metadata browser for secretbae.

pub mod app;
pub mod render;
pub mod theme;

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::Rect;
use ratatui::{Terminal, TerminalOptions, Viewport};
use sbae_proto::api::{route, ListRequest, ListResponse, PathRequest, VersionsResponse};

pub use app::{
    App, AppMode, PathFilter, RefreshInterval, SortColumn, SortCriteria, SortDirection,
    StatusMessage,
};
use crate::client::Client;

/// Terminal restoration RAII guard ensuring raw mode and alternate screen exit.
struct TerminalGuard;

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore_terminal();
    }
}

/// Restores the terminal to standard mode.
fn restore_terminal() {
    let _ = crossterm::terminal::disable_raw_mode();
    let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);
}

/// Installs a panic hook to prevent leaving the terminal corrupted after a panic.
fn install_panic_hook() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |panic_info| {
        restore_terminal();
        default_hook(panic_info);
    }));
}

/// Runs the top metadata browser.
pub fn run_top(client: &Client, interval: RefreshInterval, once: bool) -> anyhow::Result<()> {
    let mut app = App::new(client.socket_path().display().to_string());

    // Fetch initial list of secrets
    fetch_secrets(client, &mut app);

    if once {
        return render_once(&app);
    }

    run_interactive(client, &mut app, interval)
}

fn fetch_secrets(client: &Client, app: &mut App) {
    let req = ListRequest {
        prefix: None,
        tags: vec![],
    };
    match client.post::<_, ListResponse>(route::LIST, &req) {
        Ok(resp) => {
            app.set_secrets(resp.secrets);
            app.clear_status();
            app.set_last_refresh_time(format_current_time());
        }
        Err(e) => {
            app.set_status_error(e.to_string());
        }
    }
}

fn fetch_versions(client: &Client, app: &mut App) {
    if let Some(secret) = app.selected_secret() {
        let path = secret.path.clone();
        app.set_versions_loading(true);
        let req = PathRequest { path: path.clone() };
        match client.post::<_, VersionsResponse>(route::VERSIONS, &req) {
            Ok(resp) => {
                app.set_versions(path, resp.versions);
            }
            Err(e) => {
                app.set_status_error(format!("failed to fetch versions: {e}"));
                app.set_versions_loading(false);
            }
        }
    }
}

/// Frame size used when there is no terminal to ask.
const FALLBACK_SIZE: (u16, u16) = (120, 30);

/// Render a single frame without requiring a terminal.
///
/// `--once` exists to be run from scripts, cron and CI, none of which have a controlling
/// terminal. A full-screen `Terminal` queries the terminal for its size and fails without one,
/// which surfaced as a bare `Resource temporarily unavailable` that named nothing useful. A
/// fixed viewport skips both that query and the resize handling that would repeat it.
fn render_once(app: &App) -> anyhow::Result<()> {
    let (width, height) = frame_size();
    let backend = CrosstermBackend::new(std::io::stdout());
    let mut terminal = Terminal::with_options(
        backend,
        TerminalOptions { viewport: Viewport::Fixed(Rect::new(0, 0, width, height)) },
    )?;

    terminal.draw(|f| render::render(app, f))?;

    // Leave the cursor past the frame rather than on top of it, so a shell prompt or the next
    // line of script output does not overwrite the last row.
    println!();
    Ok(())
}

/// Honour the real terminal when there is one, then `COLUMNS`/`LINES`, then a sane default.
fn frame_size() -> (u16, u16) {
    if let Ok((width, height)) = crossterm::terminal::size() {
        if width > 0 && height > 0 {
            return (width, height);
        }
    }

    let from_env = |name: &str, fallback: u16| {
        std::env::var(name).ok().and_then(|value| value.parse().ok()).filter(|v| *v > 0).unwrap_or(fallback)
    };

    (from_env("COLUMNS", FALLBACK_SIZE.0), from_env("LINES", FALLBACK_SIZE.1))
}

fn run_interactive(client: &Client, app: &mut App, interval: RefreshInterval) -> anyhow::Result<()> {
    install_panic_hook();
    crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    crossterm::execute!(stdout, crossterm::terminal::EnterAlternateScreen)?;
    let _guard = TerminalGuard;

    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut last_refresh = Instant::now();

    loop {
        terminal.draw(|f| render::render(app, f))?;

        let poll_timeout = Duration::from_millis(100);
        if event::poll(poll_timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press && handle_key_input(client, app, key) {
                    break;
                }
            }
        }

        // Periodic auto-refresh
        if !app.is_paused() && last_refresh.elapsed() >= interval.as_duration() {
            fetch_secrets(client, app);
            if app.mode() == AppMode::Detail {
                fetch_versions(client, app);
            }
            last_refresh = Instant::now();
        }
    }

    Ok(())
}

fn handle_key_input(client: &Client, app: &mut App, key: crossterm::event::KeyEvent) -> bool {
    // Quit application on Ctrl+C or 'q' (outside filter typing)
    if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
        return true;
    }
    if key.code == KeyCode::Char('q') && app.mode() != AppMode::Filtering {
        return true;
    }

    match app.mode() {
        AppMode::Filtering => match key.code {
            KeyCode::Enter => app.apply_filter_input(),
            KeyCode::Esc => app.cancel_filter_input(),
            KeyCode::Backspace => app.input_filter_backspace(),
            KeyCode::Char(c) => app.input_filter_char(c),
            _ => {}
        },
        AppMode::Detail => match key.code {
            KeyCode::Esc | KeyCode::Char('h') => app.close_detail(),
            KeyCode::Up | KeyCode::Char('k') => app.select_version_prev(),
            KeyCode::Down | KeyCode::Char('j') => app.select_version_next(),
            KeyCode::Char('r') => {
                fetch_secrets(client, app);
                fetch_versions(client, app);
            }
            _ => {}
        },
        AppMode::List => match key.code {
            KeyCode::Up | KeyCode::Char('k') => app.select_prev(),
            KeyCode::Down | KeyCode::Char('j') => app.select_next(),
            KeyCode::PageUp => app.select_page_up(10),
            KeyCode::PageDown => app.select_page_down(10),
            KeyCode::Home => app.select_first(),
            KeyCode::End => app.select_last(),
            KeyCode::Enter | KeyCode::Char('l') => {
                app.open_detail();
                fetch_versions(client, app);
            }
            KeyCode::Char('/') => app.start_filtering(),
            KeyCode::Char('t') => app.cycle_tag(),
            KeyCode::Char('s') => app.cycle_sort(),
            KeyCode::Char('S') => app.reverse_sort(),
            KeyCode::Char('r') => fetch_secrets(client, app),
            KeyCode::Char('p') => app.toggle_pause(),
            _ => {}
        },
    }

    false
}

fn format_current_time() -> String {
    let now = SystemTime::now();
    if let Ok(duration) = now.duration_since(UNIX_EPOCH) {
        let secs = duration.as_secs();
        let sec = secs % 60;
        let min = (secs / 60) % 60;
        let hour = (secs / 3600) % 24;
        format!("{hour:02}:{min:02}:{sec:02} UTC")
    } else {
        "-".to_owned()
    }
}
