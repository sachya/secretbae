//! `secretbaed` -- the secretbae daemon.

#[cfg(unix)]
mod unix {
    use std::path::PathBuf;

    use sbae_daemon::{startup, Config};

    const DEFAULT_CONFIG: &str = "/etc/secretbae/config.toml";

    pub fn main() -> std::process::ExitCode {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .init();

        match run() {
            Ok(()) => std::process::ExitCode::SUCCESS,
            Err(error) => {
                // Written straight to stderr rather than through `tracing`. A daemon that
                // cannot explain why it refused to start is nearly undiagnosable under
                // systemd, and routing this through the log subsystem once made it invisible:
                // the default filter named the library target, so the binary's own fatal
                // errors were filtered out and the process exited silently with status 1.
                //
                // Nothing here can contain secret material -- these are configuration,
                // permission and capability failures.
                eprintln!("secretbaed: {error}");
                if let Some(hint) = diagnosis(&error) {
                    eprintln!("secretbaed: {hint}");
                }
                std::process::ExitCode::FAILURE
            }
        }
    }

    const CAPABILITY_HINT: &str = concat!(
        "If the daemon is running under systemd, its CapabilityBoundingSet is probably too ",
        "narrow: reading the store as root needs CAP_DAC_OVERRIDE and CAP_FOWNER alongside ",
        "CAP_CHOWN, because root's permission-check bypass is itself a capability."
    );

    /// Turn the failures that are really deployment mistakes into the instruction that fixes
    /// them, because the underlying errno says nothing about the unit file that caused it.
    fn diagnosis(error: &sbae_daemon::DaemonError) -> Option<&'static str> {
        use sbae_daemon::DaemonError;

        match error {
            DaemonError::Harden("mlockall", _) => Some(
                "mlockall was refused. The service needs LimitMEMLOCK=128M in its unit: \
                 MCL_FUTURE keeps locking pages for the life of the process, and CAP_IPC_LOCK \
                 is surrendered at the privilege drop.",
            ),
            // Reaching the store is the first thing a too-narrow bounding set breaks, and the
            // failure arrives as a bare "unable to open database file" from SQLite that names
            // no capability at all.
            DaemonError::Io(source) if source.kind() == std::io::ErrorKind::PermissionDenied => {
                Some(CAPABILITY_HINT)
            }
            DaemonError::Store(_) => Some(CAPABILITY_HINT),
            DaemonError::NotRoot => {
                Some("Start it via systemd, or as root -- the keyfile is readable only by root.")
            }
            DaemonError::NotInitialised | DaemonError::Keyfile { .. } => {
                Some("If this host has not been set up yet, run `secretbaed init` first.")
            }
            DaemonError::MemlockTooLow { .. } => Some(
                "Set LimitMEMLOCK=128M in the unit, or raise it with `ulimit -l` when \
                 running the daemon by hand.",
            ),
            _ => None,
        }
    }

    fn run() -> sbae_daemon::Result<()> {
        let mut arguments = std::env::args().skip(1);
        let first = arguments.next();
        let initialising = first.as_deref() == Some("init");

        let config_path = if initialising {
            arguments.next()
        } else {
            first
        }
        .map_or_else(|| PathBuf::from(DEFAULT_CONFIG), PathBuf::from);
        let config = Config::load(&config_path)?;

        if initialising {
            let token = startup::initialise(&config)?;
            // The only time this value is ever displayed. It cannot be recovered afterwards,
            // because only its hash is stored.
            println!("{token}");
            eprintln!(
                "{}",
                concat!(
                    "Root token issued above -- store it now, it cannot be shown again. ",
                    "It is bound to uid 0, so it works only from root."
                )
            );
            return Ok(());
        }

        // The privileged sequence is deliberately synchronous and runs before any runtime
        // exists, so no task can observe the process while it still holds root.
        let (listeners, state) = startup::run(&config)?;

        tracing::info!(
            socket = %config.socket.display(),
            resolve_socket = %config.resolve_socket.display(),
            user = %config.user,
            "serving"
        );

        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(async {
                // Either listener failing is fatal to the daemon, matching today's
                // single-listener behaviour; `try_join!` drops the other future the instant
                // one errors, so its graceful shutdown does not get to run in that case.
                let api = sbae_daemon::server::serve(listeners.api, state.clone());
                let resolve = sbae_daemon::resolve_socket::serve(listeners.resolve, state);
                tokio::try_join!(api, resolve)?;
                Ok(())
            })
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    unix::main()
}

#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "secretbaed runs on Linux only: it depends on Unix domain sockets, SO_PEERCRED \
         peer credentials, mlock and setresuid."
    );
    std::process::ExitCode::FAILURE
}
