//! A minimal, line-based protocol for reading secrets, for a caller that cannot afford an HTTP
//! client and a JSON parser in its own language -- see `docs/API.md` for the exact wire format
//! and example clients. Unlike `/v1/resolve`, this is meant to be called from an application's
//! own long-running process whenever it needs a fresh value, not just once at start the way
//! `secretbae exec` uses the HTTP route.
//!
//! Runs on a second Unix socket, gated by the identical three checks as the HTTP API -- token,
//! `SO_PEERCRED`, policy -- scoped to exactly the same `Capability::Read` grant as `/v1/resolve`.
//! The only genuinely new surface here is the parser, which is why it is kept deliberately small
//! and bounded: a fixed line-length cap, a fixed path-count cap, and a read timeout on every
//! step, none of which axum/hyper need spelling out for the HTTP listener.

use std::os::unix::net::UnixListener as StdUnixListener;
use std::time::Duration;

use sbae_policy::PresentedToken;
use sbae_proto::api::{self, route};
use sbae_proto::{SecretPath, Version};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::net::{UnixListener, UnixStream};

use crate::auth::{authorize, Denied, Requested, DENIED_MESSAGE};
use crate::routes::{resolve_secrets, ResolveFailure, ResolveTarget, ResolvedSecret};
use crate::{Result, SharedState};

/// A stalled read (no data, or no line terminator) beyond this is treated as the client having
/// gone away.
const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The whole exchange, however many paths are requested, must finish inside this -- a client
/// trickling data just under `READ_TIMEOUT` on every read cannot hold a connection open forever.
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn serve(listener: StdUnixListener, state: SharedState) -> Result<()> {
    let listener = UnixListener::from_std(listener)?;

    let accept_loop = async {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                // A single failed accept (e.g. the process ran out of file descriptors for a
                // moment) must not bring down the listener.
                continue;
            };
            let state = state.clone();
            tokio::spawn(async move {
                let _ = tokio::time::timeout(CONNECTION_TIMEOUT, handle(stream, state)).await;
            });
        }
    };

    tokio::select! {
        () = accept_loop => {}
        () = crate::server::shutdown_signal() => {}
    }
    Ok(())
}

/// What one connection asked for, or why it never got that far.
enum ParsedRequest {
    /// The peer disconnected before sending anything -- a clean close, not a violation.
    Disconnected,
    /// A framing rule was broken. Carries the reason for the audit log only.
    Violation(&'static str),
    Ready {
        token: String,
        targets: Vec<ResolveTarget>,
    },
}

async fn handle(stream: UnixStream, state: SharedState) {
    let peer = crate::server::peer_credentials(&stream);
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);

    match read_request(&mut reader).await {
        ParsedRequest::Disconnected => {}
        ParsedRequest::Violation(reason) => {
            // Audited the same way a malformed token would be, even though the connection
            // never got far enough to present one: `peer` is already known from SO_PEERCRED
            // regardless of what the client sends.
            let _ = authorize(
                &state,
                Err(Denied::ProtocolViolation(reason)),
                peer,
                &Requested {
                    route: route::RESOLVE,
                    path: None,
                },
            );
            let _ = respond_error(&mut write_half, DENIED_MESSAGE).await;
        }
        ParsedRequest::Ready { token, targets } => {
            let result = resolve_secrets(&state, peer, &targets, || {
                PresentedToken::parse(&token).map_err(|_| Denied::MalformedToken)
            });
            let _ = respond(&mut write_half, result).await;
        }
    }
}

/// `RESOLVE 1 <token> <path-count>\n`, then exactly `<path-count>` lines of
/// `<path>[@<version>]\n`. Every field is validated before the next line is read.
async fn read_request(reader: &mut BufReader<OwnedReadHalf>) -> ParsedRequest {
    let first = match timed_read_line(reader).await {
        Ok(Some(line)) => line,
        Ok(None) => return ParsedRequest::Disconnected,
        Err(reason) => return ParsedRequest::Violation(reason),
    };

    let mut fields = first.splitn(4, ' ');
    let (Some(verb), Some(version), Some(token), Some(count)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        return ParsedRequest::Violation("malformed request line");
    };
    if fields.next().is_some() || token.is_empty() {
        return ParsedRequest::Violation("malformed request line");
    }
    if verb != api::RESOLVE_SOCKET_VERB {
        return ParsedRequest::Violation("unknown verb");
    }
    let Ok(version) = version.parse::<u32>() else {
        return ParsedRequest::Violation("malformed protocol version");
    };
    if version != api::RESOLVE_SOCKET_VERSION {
        return ParsedRequest::Violation("unsupported protocol version");
    }
    let Ok(count) = count.parse::<usize>() else {
        return ParsedRequest::Violation("malformed path count");
    };
    if count > api::RESOLVE_SOCKET_MAX_PATHS {
        return ParsedRequest::Violation("too many paths requested");
    }

    let mut targets = Vec::with_capacity(count);
    for _ in 0..count {
        let line = match timed_read_line(reader).await {
            Ok(Some(line)) => line,
            Ok(None) => return ParsedRequest::Violation("request truncated"),
            Err(reason) => return ParsedRequest::Violation(reason),
        };

        let (path_str, version_str) = line
            .rsplit_once('@')
            .map_or((line.as_str(), None), |(path, version)| {
                (path, Some(version))
            });

        let Ok(path) = path_str.parse::<SecretPath>() else {
            return ParsedRequest::Violation("malformed path");
        };
        let version = match version_str {
            None => None,
            Some(raw) => match raw.parse::<Version>() {
                Ok(version) => Some(version),
                Err(_) => return ParsedRequest::Violation("malformed version"),
            },
        };
        targets.push(ResolveTarget { path, version });
    }

    ParsedRequest::Ready {
        token: token.to_owned(),
        targets,
    }
}

async fn timed_read_line(
    reader: &mut BufReader<OwnedReadHalf>,
) -> core::result::Result<Option<String>, &'static str> {
    match tokio::time::timeout(READ_TIMEOUT, read_capped_line(reader)).await {
        Ok(Ok(line)) => Ok(line),
        Ok(Err(_)) => Err("line too long or not valid UTF-8"),
        Err(_) => Err("timed out waiting for the client"),
    }
}

/// Reads one line, stripping the trailing `\n`. `Ok(None)` means the peer closed the connection
/// before writing anything at all. A line at or past `RESOLVE_SOCKET_MAX_LINE_BYTES` with no
/// terminator in that span is reported as an error rather than read indefinitely.
async fn read_capped_line(
    reader: &mut BufReader<OwnedReadHalf>,
) -> std::io::Result<Option<String>> {
    let mut buf = Vec::new();
    let read = reader
        .take(api::RESOLVE_SOCKET_MAX_LINE_BYTES as u64)
        .read_until(b'\n', &mut buf)
        .await?;
    if read == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "line too long",
        ));
    }
    buf.pop();
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "not valid UTF-8"))
}

async fn respond(
    write_half: &mut OwnedWriteHalf,
    result: core::result::Result<Vec<ResolvedSecret>, ResolveFailure>,
) -> std::io::Result<()> {
    match result {
        Ok(resolved) => {
            for item in resolved {
                let bytes = item.plaintext.expose();
                let header = format!("VALUE {} {}\n", item.version, bytes.len());
                write_half.write_all(header.as_bytes()).await?;
                write_half.write_all(bytes).await?;
            }
            write_half.flush().await
        }
        Err(failure) => respond_error(write_half, failure.message()).await,
    }
}

async fn respond_error(write_half: &mut OwnedWriteHalf, message: &str) -> std::io::Result<()> {
    write_half
        .write_all(format!("ERROR {message}\n").as_bytes())
        .await?;
    write_half.flush().await
}
