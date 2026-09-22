//! Rotation, backup and restore.
//!
//! Each of these changes or copies the entire store, so each confirms intent before acting:
//! a mistyped `rekey` is survivable but alarming, and a `backup` written under a passphrase
//! the operator did not mean to use is unrecoverable in the way that matters -- they find out
//! only when they try to restore it.

use std::io::{IsTerminal as _, Write as _};
use std::path::Path;

use anyhow::{bail, Context as _};
use data_encoding::BASE64;
use sbae_proto::api::{self, route};
use zeroize::Zeroize as _;

use crate::client::Client;

pub fn rekey(client: &Client, skip_confirmation: bool, json: bool) -> anyhow::Result<()> {
    if !skip_confirmation && !confirm("Rotate the master key and rewrap every stored data key?")? {
        bail!("cancelled");
    }

    let response: api::RekeyResponse = client.post(route::REKEY, &serde_json::json!({}))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "Rotated to generation {}: {} versions rewrapped, {} audit entries re-keyed.",
            response.generation, response.versions_rewrapped, response.audit_entries_rekeyed
        );
    }
    Ok(())
}

pub fn backup(
    client: &Client,
    output: &Path,
    passphrase: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    if output.exists() {
        bail!("{} already exists; refusing to overwrite a backup", output.display());
    }

    let mut passphrase = match passphrase {
        Some(supplied) => supplied,
        None => prompt_new_passphrase()?,
    };

    let request = api::BackupRequest { passphrase: passphrase.clone() };
    let sent: anyhow::Result<api::BackupResponse> = client.post(route::BACKUP, &request);
    passphrase.zeroize();
    let response = sent?;

    let bundle = BASE64
        .decode(response.bundle.as_bytes())
        .context("daemon returned a bundle that is not base64")?;

    write_private(output, &bundle)
        .with_context(|| format!("writing {}", output.display()))?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "Wrote {} ({} secrets, {} versions).\n\
             The bundle is encrypted with the passphrase you supplied, not the server keyfile -- \
             losing it means losing the backup.",
            output.display(),
            response.secrets,
            response.versions
        );
    }
    Ok(())
}

pub fn restore(
    client: &Client,
    input: &Path,
    passphrase: Option<String>,
    json: bool,
) -> anyhow::Result<()> {
    let bundle = std::fs::read(input)
        .with_context(|| format!("reading {}", input.display()))?;

    let mut passphrase = match passphrase {
        Some(supplied) => supplied,
        None => prompt("Bundle passphrase: ")?,
    };

    let request = api::RestoreRequest {
        passphrase: passphrase.clone(),
        bundle: BASE64.encode(&bundle),
    };
    let response: anyhow::Result<api::RestoreResponse> = client.post(route::RESTORE, &request);
    passphrase.zeroize();
    let response = response?;

    if json {
        println!("{}", serde_json::to_string_pretty(&response)?);
    } else {
        println!(
            "Restored {} secrets ({} versions) and {} policies.\n\
             Tokens are not carried in a bundle -- issue fresh ones with `secretbae token create`.",
            response.secrets, response.versions, response.policies
        );
    }
    Ok(())
}

/// Write owner-only from the outset, so the bundle is never briefly readable by others.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }

    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// Refuse to prompt when there is nobody to answer.
///
/// Reading from a redirected stdin does not fail, it silently eats the next line of whatever
/// was being piped in -- so a scripted `ssh host < script.sh` would answer the prompt with an
/// unrelated command and then skip it. Better to stop and name the flag that avoids the
/// question entirely.
fn require_interactive(instead: &str) -> anyhow::Result<()> {
    if std::io::stdin().is_terminal() {
        return Ok(());
    }
    bail!("stdin is not a terminal, so there is nobody to prompt: {instead}");
}

fn confirm(question: &str) -> anyhow::Result<bool> {
    require_interactive("pass --yes to confirm non-interactively")?;

    print!("{question} [y/N] ");
    std::io::stdout().flush()?;

    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// Asked twice, because a passphrase typo is only discovered when a restore is attempted --
/// usually the worst possible moment.
fn prompt_new_passphrase() -> anyhow::Result<String> {
    let first = prompt("Passphrase for the bundle: ")?;
    if first.trim().is_empty() {
        bail!("a backup passphrase is required");
    }

    let mut second = prompt("Repeat the passphrase: ")?;
    let matched = first == second;
    second.zeroize();

    if !matched {
        bail!("the passphrases did not match");
    }
    Ok(first)
}

/// Read a passphrase without echoing it.
///
/// Raw mode keeps the characters off the terminal entirely, so the passphrase reaches neither
/// anyone watching the screen nor the scrollback the operator leaves behind. Raw mode is
/// restored on every exit path, including an error part-way through the read.
fn prompt(message: &str) -> anyhow::Result<String> {
    require_interactive("set SECRETBAE_BACKUP_PASSPHRASE, or pass --passphrase")?;

    print!("{message}");
    std::io::stdout().flush()?;

    crossterm::terminal::enable_raw_mode()?;
    let typed = read_without_echo();
    let _ = crossterm::terminal::disable_raw_mode();
    println!();

    typed
}

fn read_without_echo() -> anyhow::Result<String> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

    let mut typed = String::new();
    loop {
        let Event::Key(key) = event::read()? else { continue };

        // Windows terminals report both press and release; counting both would double every
        // character.
        if key.kind == KeyEventKind::Release {
            continue;
        }

        match key.code {
            KeyCode::Enter => return Ok(typed),
            KeyCode::Backspace => {
                typed.pop();
            }
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                typed.zeroize();
                bail!("cancelled");
            }
            KeyCode::Char(character) => typed.push(character),
            _ => {}
        }
    }
}
