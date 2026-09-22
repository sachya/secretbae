//! HTTP/1.1 client communicating over a Unix domain socket.
//!
//! A synchronous, hand-rolled HTTP/1.1 implementation directly over Unix domain sockets was
//! chosen over `hyper` and `tokio` for specific architectural reasons:
//! 1. The CLI is synchronous: commands perform at most one or two sequential requests before
//!    exiting or replacing the process via `execve`. Pulling in `tokio`, `hyper`, and
//!    `hyper-util` would introduce an asynchronous runtime and dozens of transitive dependencies
//!    with zero concurrency benefit.
//! 2. The daemon's wire contract is strictly HTTP/1.1 POST with JSON bodies over a local socket.
//! 3. A minimal blocking implementation is self-contained, auditable, and eliminates hidden
//!    runtime state.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sbae_proto::api::{ErrorResponse, AUTH_HEADER, BEARER_PREFIX};
use serde::de::DeserializeOwned;
use serde::Serialize;

/// Socket path domain wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocketPath(PathBuf);

impl SocketPath {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self(path)
    }

    #[must_use]
    pub fn as_path(&self) -> &Path {
        &self.0
    }
}

/// A synchronous HTTP client communicating with the daemon.
#[derive(Clone, Debug)]
pub struct Client {
    socket_path: PathBuf,
    token: Option<String>,
}

impl Client {
    #[must_use]
    pub fn new(socket_path: impl Into<PathBuf>, token: Option<String>) -> Self {
        Self {
            socket_path: socket_path.into(),
            token,
        }
    }

    #[must_use]
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    #[must_use]
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn post<Req: Serialize, Resp: DeserializeOwned>(
        &self,
        route: &str,
        request: &Req,
    ) -> anyhow::Result<Resp> {
        #[cfg(unix)]
        {
            let mut stream = std::os::unix::net::UnixStream::connect(&self.socket_path)
                .map_err(|e| anyhow::anyhow!("failed to connect to daemon socket '{}': {e}", self.socket_path.display()))?;
            send_http_request(&mut stream, route, self.token.as_deref(), request)
        }

        #[cfg(not(unix))]
        {
            let _ = (route, request);
            anyhow::bail!("Unix domain sockets are not supported on this platform")
        }
    }
}

/// Formats and transmits an HTTP/1.1 POST request over any stream and parses the response.
pub fn send_http_request<Req: Serialize, Resp: DeserializeOwned, S: Read + Write>(
    stream: &mut S,
    route: &str,
    token: Option<&str>,
    request: &Req,
) -> anyhow::Result<Resp> {
    let body_bytes = serde_json::to_vec(request)
        .map_err(|e| anyhow::anyhow!("failed to serialize request JSON: {e}"))?;

    let mut header = format!(
        "POST {route} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n",
        body_bytes.len()
    );
    if let Some(tok) = token {
        use std::fmt::Write as _;
        let _ = write!(header, "{AUTH_HEADER}: {BEARER_PREFIX}{tok}\r\n");
    }
    header.push_str("\r\n");

    stream
        .write_all(header.as_bytes())
        .map_err(|e| anyhow::anyhow!("failed to write HTTP request headers: {e}"))?;
    stream
        .write_all(&body_bytes)
        .map_err(|e| anyhow::anyhow!("failed to write HTTP request payload: {e}"))?;
    stream
        .flush()
        .map_err(|e| anyhow::anyhow!("failed to flush HTTP request: {e}"))?;

    parse_http_response(stream)
}

/// Reads and parses an HTTP/1.1 response from a stream.
pub fn parse_http_response<Resp: DeserializeOwned, R: Read>(stream: &mut R) -> anyhow::Result<Resp> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    let header_end_pos;

    loop {
        let n = stream
            .read(&mut chunk)
            .map_err(|e| anyhow::anyhow!("failed to read from daemon: {e}"))?;
        if n == 0 {
            anyhow::bail!("daemon closed socket prematurely before completing HTTP headers");
        }
        buffer.extend_from_slice(&chunk[..n]);

        if let Some(pos) = buffer.windows(4).position(|w| w == b"\r\n\r\n") {
            header_end_pos = pos;
            break;
        }
    }

    let header_bytes = &buffer[..header_end_pos];
    let body_start = header_end_pos + 4;
    let header_text = std::str::from_utf8(header_bytes)
        .map_err(|e| anyhow::anyhow!("daemon returned non-UTF-8 HTTP headers: {e}"))?;

    let mut lines = header_text.lines();
    let status_line = lines.next().ok_or_else(|| anyhow::anyhow!("empty HTTP response"))?;

    let mut status_parts = status_line.split_whitespace();
    let _proto = status_parts.next().ok_or_else(|| anyhow::anyhow!("invalid HTTP status line"))?;
    let status_code_str = status_parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("missing status code in HTTP status line"))?;
    let status_code: u16 = status_code_str
        .parse()
        .map_err(|_| anyhow::anyhow!("malformed status code '{status_code_str}' in HTTP response"))?;

    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            if name.trim().eq_ignore_ascii_case("content-length") {
                content_length = val.trim().parse::<usize>().ok();
            }
        }
    }

    let mut body = buffer[body_start..].to_vec();
    if let Some(expected_len) = content_length {
        while body.len() < expected_len {
            let needed = expected_len - body.len();
            let to_read = needed.min(chunk.len());
            let n = stream
                .read(&mut chunk[..to_read])
                .map_err(|e| anyhow::anyhow!("failed to read HTTP body from daemon: {e}"))?;
            if n == 0 {
                anyhow::bail!(
                    "daemon closed socket prematurely; expected {expected_len} bytes, received {}",
                    body.len()
                );
            }
            body.extend_from_slice(&chunk[..n]);
        }
    } else {
        loop {
            let n = stream
                .read(&mut chunk)
                .map_err(|e| anyhow::anyhow!("failed to read HTTP body: {e}"))?;
            if n == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..n]);
        }
    }

    if (200..=299).contains(&status_code) {
        serde_json::from_slice::<Resp>(&body)
            .map_err(|e| anyhow::anyhow!("failed to parse daemon JSON response: {e}"))
    } else {
        if let Ok(err_resp) = serde_json::from_slice::<ErrorResponse>(&body) {
            anyhow::bail!("{}", err_resp.error);
        }
        let raw_err = String::from_utf8_lossy(&body);
        anyhow::bail!("daemon error (HTTP {status_code}): {raw_err}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct MockStream {
        read_buf: Cursor<Vec<u8>>,
        write_buf: Vec<u8>,
    }

    impl MockStream {
        fn new(response_bytes: Vec<u8>) -> Self {
            Self {
                read_buf: Cursor::new(response_bytes),
                write_buf: Vec::new(),
            }
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read_buf.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write_buf.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn send_http_request_serializes_headers_and_parses_json_response() {
        let response_data = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\nConnection: close\r\n\r\n{\"ok\":true}";
        let mut stream = MockStream::new(response_data.to_vec());

        let req = serde_json::json!({"path": "prod/db"});
        let resp: sbae_proto::api::Ack =
            send_http_request(&mut stream, "/v1/test", Some("my_token"), &req).unwrap();

        assert!(resp.ok);

        let written = String::from_utf8(stream.write_buf).unwrap();
        assert!(written.starts_with("POST /v1/test HTTP/1.1\r\n"));
        assert!(written.contains("authorization: Bearer my_token\r\n"));
        assert!(written.contains("content-type: application/json\r\n") || written.contains("Content-Type: application/json\r\n"));
        assert!(written.ends_with("{\"path\":\"prod/db\"}"));
    }

    #[test]
    fn daemon_error_responses_are_extracted_cleanly() {
        let body = b"{\"error\":\"not found or not permitted\"}";
        let response_data = format!(
            "HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            std::str::from_utf8(body).unwrap()
        );
        let mut stream = MockStream::new(response_data.into_bytes());

        let req = serde_json::json!({});
        let result: Result<sbae_proto::api::Ack, _> =
            send_http_request(&mut stream, "/v1/test", None, &req);

        let err = result.unwrap_err();
        assert_eq!(err.to_string(), "not found or not permitted");
    }
}