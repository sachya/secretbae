//! Binary entry point for secretbae.

#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() -> anyhow::Result<()> {
    sbae_cli::run()
}

#[cfg(not(unix))]
fn main() {
    eprintln!("secretbae is only supported on Linux and Unix platforms.");
    std::process::exit(1);
}