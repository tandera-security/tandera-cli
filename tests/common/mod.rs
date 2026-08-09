//! Shared `TcpListener`-stub scaffolding for the integration tests under
//! `tests/`. Previously duplicated byte-for-byte across `http_stub.rs`,
//! `finding_flow.rs`, and `import_pipeline.rs` (plus a smaller variant in
//! `read_surface.rs`); consolidated here so each test file just does `mod
//! common;` and pulls in whichever pieces it needs.
//!
//! Rust integration-test convention: a file at `tests/common/mod.rs` (as
//! opposed to `tests/common.rs`, which would be discovered by cargo as its
//! own top-level test binary) is NOT itself compiled as a test target — it's
//! only pulled in by the files that declare `mod common;`. Different test
//! binaries use different subsets of these helpers, so `dead_code` is
//! allowed wholesale rather than fighting per-binary unused warnings.
#![allow(dead_code)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

/// One request as observed by a stub server.
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl RecordedRequest {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// Reads one HTTP request off `stream` (headers, then the body up to
/// `Content-Length`) and parses it into a `RecordedRequest`.
pub fn read_request(stream: &mut TcpStream) -> RecordedRequest {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("set read timeout");

    let mut data = Vec::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = stream.read(&mut buf).unwrap_or(0);
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buf[..n]);

        let text = String::from_utf8_lossy(&data);
        let Some(header_end) = text.find("\r\n\r\n") else {
            continue;
        };
        let headers_part = &text[..header_end];
        let body_so_far = text.len() - (header_end + 4);
        let content_length: usize = headers_part
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                k.eq_ignore_ascii_case("content-length")
                    .then(|| v.trim().parse().unwrap_or(0))
            })
            .unwrap_or(0);
        if body_so_far >= content_length {
            break;
        }
    }

    let text = String::from_utf8_lossy(&data).to_string();
    let mut parts = text.splitn(2, "\r\n\r\n");
    let head = parts.next().unwrap_or("");
    let body = parts.next().unwrap_or("").to_string();

    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut rl_parts = request_line.split_whitespace();
    let method = rl_parts.next().unwrap_or("").to_string();
    let path = rl_parts.next().unwrap_or("").to_string();
    let headers = lines
        .filter_map(|l| {
            l.split_once(':')
                .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    RecordedRequest {
        method,
        path,
        headers,
        body,
    }
}

/// Builds a full raw HTTP response with a correctly computed
/// `Content-Length` — hardcoding that byte count by hand is exactly the kind
/// of off-by-one that silently breaks response framing and is easy to get
/// wrong when a body literal is edited later.
pub fn http_response(status_line: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
}

/// Binds a loopback listener, accepts exactly ONE connection, records the
/// request, replies with `response` (a full raw HTTP response, status line
/// through body), and sends the recorded request back over the returned
/// channel. Returns `http://127.0.0.1:<port>` as the base URL to point an
/// `ApiClient` at. For a single request/response exchange; see `spawn_stub`
/// for a sequence of several.
pub fn spawn_stub_server(response: String) -> (String, mpsc::Receiver<RecordedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub listener");
    let addr = listener.local_addr().expect("stub listener addr");
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let recorded = read_request(&mut stream);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            let _ = tx.send(recorded);
        }
    });

    (format!("http://{addr}"), rx)
}

/// Binds a loopback listener and serves `count` sequential requests, each
/// answered by `handler(request, base_url)`. Returns the `http://` base URL
/// and a channel that yields one `RecordedRequest` per request, in order.
/// For a sequence of several requests against one listener (e.g. a
/// presigned-upload pipeline); see `spawn_stub_server` for a single
/// request/response exchange.
pub fn spawn_stub<F>(count: usize, handler: F) -> (String, mpsc::Receiver<RecordedRequest>)
where
    F: Fn(&RecordedRequest, &str) -> String + Send + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub listener");
    let addr = listener.local_addr().expect("stub listener addr");
    let base = format!("http://{addr}");
    let base_for_thread = base.clone();
    let (tx, rx) = mpsc::channel();

    thread::spawn(move || {
        for _ in 0..count {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let recorded = read_request(&mut stream);
            let response = handler(&recorded, &base_for_thread);
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
            if tx.send(recorded).is_err() {
                break;
            }
        }
    });

    (base, rx)
}

/// Spawn a one-shot HTTP server returning `body` for the first request; the
/// raw request text is captured (as opposed to `RecordedRequest`'s parsed
/// shape) so a test can assert directly against it, e.g. a query string
/// embedded in the request line. Used by `read_surface.rs`, which only cares
/// about the request line, not the fully parsed method/path/headers/body.
pub fn serve_once(body: &'static str) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            tx.send(req).ok();
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            stream.write_all(resp.as_bytes()).ok();
        }
    });
    (addr, rx)
}
