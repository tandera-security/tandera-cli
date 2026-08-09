//! Thin blocking HTTP client wrapper around the Tandera API. URL/header
//! construction is split into pure, unit-testable functions
//! (`build_url`/`bearer_header`) from the actual request execution, and
//! error classification (`classify_error`) distinguishes the two statuses
//! the CLI's commands special-case — 401 and 402 — from everything else.

use std::time::Duration;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::models::ApiErrorBody;

const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A failed API call. Distinguishes `Unauthorized` (401 — bad/expired
/// token) and `PaymentRequired` (402 — plan entitlement gate, e.g. missing
/// `AiAuthoring`) since `auth login`/`auth status`/`findings ai-draft`
/// each special-case exactly one of these; every other non-2xx status
/// collapses to `Http`.
#[derive(Debug)]
pub enum ApiError {
    Unauthorized(String),
    PaymentRequired(String),
    Http { status: u16, message: String },
    Transport(String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Unauthorized(msg) => write!(f, "unauthorized: {msg}"),
            ApiError::PaymentRequired(msg) => write!(f, "payment required: {msg}"),
            ApiError::Http { status, message } => write!(f, "API error ({status}): {message}"),
            ApiError::Transport(msg) => write!(f, "request failed: {msg}"),
        }
    }
}

impl std::error::Error for ApiError {}

/// Joins `api_url` and `path` with exactly one `/` between them, regardless
/// of whether `api_url` has a trailing slash. Pure — no network, no I/O.
pub fn build_url(api_url: &str, path: &str) -> String {
    format!("{}{}", api_url.trim_end_matches('/'), path)
}

/// The `Authorization` header value for a bearer token. Pure — kept
/// separate from request construction so it (and the "never the full token
/// anywhere but here, and even here it's the real value on purpose — this
/// is the one place it's SUPPOSED to appear, in a header, not printed to a
/// human") is independently testable.
pub fn bearer_header(token: &str) -> String {
    format!("Bearer {token}")
}

// `Clone` is cheap: `reqwest::blocking::Client` is `Arc`-backed internally
// (cloning shares the connection pool), and `api_url`/`token` are small
// owned strings. Needed so the REPL can hand a copy to a background thread
// (status/credits fetches) while keeping its own copy on the `Session`.
#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::blocking::Client,
    api_url: String,
    token: Option<String>,
}

impl ApiClient {
    pub fn new(api_url: impl Into<String>, token: Option<String>) -> Result<Self> {
        let http = reqwest::blocking::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .context("failed to build HTTP client")?;
        Ok(Self {
            http,
            api_url: api_url.into(),
            token,
        })
    }

    /// The API base URL this client targets (e.g. `https://api.tandera.io`).
    /// Used to derive the console URL for `:portal`.
    pub fn base_url(&self) -> &str {
        &self.api_url
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::blocking::RequestBuilder {
        let url = build_url(&self.api_url, path);
        let mut req = self.http.request(method, url);
        if let Some(token) = &self.token {
            req = req.header(reqwest::header::AUTHORIZATION, bearer_header(token));
        }
        req
    }

    pub fn get_json<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let resp = self
            .request(reqwest::Method::GET, path)
            .send()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        handle_response(resp)
    }

    /// GET `path` with a URL-encoded query string. Values are percent-encoded
    /// by reqwest's `.query()`.
    pub fn get_json_query<T: DeserializeOwned>(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<T, ApiError> {
        let resp = self
            .request(reqwest::Method::GET, path)
            .query(query)
            .send()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        handle_response(resp)
    }

    pub fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let resp = self
            .request(reqwest::Method::POST, path)
            .json(body)
            .send()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        handle_response(resp)
    }

    /// PUT a JSON body to a Tandera API `path` (authenticated, same as
    /// `post_json` but the PUT verb) — used for partial updates like binding a
    /// client to an assessment.
    pub fn put_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<T, ApiError> {
        let resp = self
            .request(reqwest::Method::PUT, path)
            .json(body)
            .send()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        handle_response(resp)
    }

    /// PUT a JSON body to `path` and discard the response body — for
    /// endpoints that reply `200`/`204` with nothing to parse, like applying
    /// a methodology to an assessment. `put_json` would fail on exactly
    /// that response (`resp.json::<T>()` errors on an empty body), so this
    /// is the status-only sibling: same request shape as `put_json`, but it
    /// only ever inspects the status code, the same way `probe_auth` does.
    pub fn put_json_no_content<B: Serialize>(&self, path: &str, body: &B) -> Result<(), ApiError> {
        let resp = self
            .request(reqwest::Method::PUT, path)
            .json(body)
            .send()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        Err(classify_error(status, resp))
    }

    /// PUT raw bytes to an **arbitrary** URL — namely a presigned S3 upload
    /// URL handed back by `POST .../imports/upload-url`. Deliberately built
    /// directly on `self.http` rather than going through `self.request`
    /// (which injects the `Authorization: Bearer <PAT>` header): S3 is a
    /// third party from the Tandera API's point of view, and attaching our
    /// personal access token to a request bound for it would leak the
    /// credential. Only `Content-Type` and the body are sent. A non-2xx S3
    /// response (any status other than the typical 200/204) is surfaced as
    /// an `ApiError`.
    pub fn put_bytes_to_url(
        &self,
        url: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<(), ApiError> {
        let resp = self
            .http
            .put(url)
            .header(reqwest::header::CONTENT_TYPE, content_type)
            .body(body)
            .send()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        Err(classify_error(status, resp))
    }

    /// A lightweight authed probe (`GET /v1/assessments`) — used by `auth
    /// login` (to verify a token before ever storing it) and `auth status`
    /// (to confirm a stored token still works). Doesn't care about the
    /// response body shape, only the status.
    pub fn probe_auth(&self) -> Result<(), ApiError> {
        let resp = self
            .request(reqwest::Method::GET, "/v1/assessments")
            .send()
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        let status = resp.status();
        if status.is_success() {
            return Ok(());
        }
        Err(classify_error(status, resp))
    }
}

fn handle_response<T: DeserializeOwned>(resp: reqwest::blocking::Response) -> Result<T, ApiError> {
    let status = resp.status();
    if status.is_success() {
        return resp
            .json::<T>()
            .map_err(|e| ApiError::Transport(format!("failed to parse response body: {e}")));
    }
    Err(classify_error(status, resp))
}

fn classify_error(status: reqwest::StatusCode, resp: reqwest::blocking::Response) -> ApiError {
    let text = resp.text().unwrap_or_default();
    let message = serde_json::from_str::<ApiErrorBody>(&text)
        .map(|b| b.error.message)
        .unwrap_or(text);
    match status.as_u16() {
        401 => ApiError::Unauthorized(message),
        402 => ApiError::PaymentRequired(message),
        code => ApiError::Http {
            status: code,
            message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_url_joins_with_exactly_one_slash() {
        assert_eq!(
            build_url("https://api.tandera.io", "/v1/assessments"),
            "https://api.tandera.io/v1/assessments"
        );
        assert_eq!(
            build_url("https://api.tandera.io/", "/v1/assessments"),
            "https://api.tandera.io/v1/assessments"
        );
    }

    #[test]
    fn bearer_header_format() {
        assert_eq!(
            bearer_header("tandera_pat_abc123"),
            "Bearer tandera_pat_abc123"
        );
    }
}
