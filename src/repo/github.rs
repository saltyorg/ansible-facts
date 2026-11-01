//! Compares the local commit with official Saltbox on GitHub.
//!
//! Requests go through the svm proxy first, which shields Saltbox hosts from
//! GitHub API caching and rate limits, then directly to GitHub when svm does
//! not return a usable response. Results are never cached locally.

use futures_util::TryStreamExt;
use reqwest::{Client, StatusCode};
use serde_json::Value;
use std::time::Duration;

pub const SVM_PREFIX: &str = "https://svm.saltbox.dev/version?url=";
pub const GITHUB_API_BASE: &str = "https://api.github.com";
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const REPOSITORY: &str = "saltyorg/Saltbox";
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const USER_AGENT: &str = concat!("saltbox-facts/", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Copy)]
pub struct ApiConfig<'a> {
    pub svm_prefix: &'a str,
    pub api_base: &'a str,
    pub request_timeout: Duration,
}

impl Default for ApiConfig<'static> {
    fn default() -> Self {
        Self {
            svm_prefix: SVM_PREFIX,
            api_base: GITHUB_API_BASE,
            request_timeout: REQUEST_TIMEOUT,
        }
    }
}

#[derive(Debug, Default, Eq, PartialEq)]
pub struct Comparison {
    pub status: &'static str,
    pub ahead_by: Option<u64>,
    pub behind_by: Option<u64>,
    pub upstream_commit: Option<String>,
    /// `svm` or `github`: which endpoint produced the decisive response.
    pub source: Option<&'static str>,
    pub error: Option<String>,
}

#[derive(Debug)]
struct Response {
    status: StatusCode,
    body: Value,
    source: &'static str,
}

/// Compares `base` (an upstream branch) with `commit`.
pub async fn compare(
    client: &Client,
    config: ApiConfig<'_>,
    base: &str,
    commit: &str,
) -> Comparison {
    if !is_queryable_branch(base) {
        return unknown(
            None,
            format!("Branch name '{base}' cannot be queried upstream"),
        );
    }

    let compare_path = format!("/repos/{REPOSITORY}/compare/{base}...{commit}?per_page=1");
    let response = match get(client, config, &compare_path).await {
        Ok(response) => response,
        Err(error) => return unknown(None, error),
    };
    if response.status == StatusCode::OK {
        return parse_comparison(&response.body, response.source);
    }

    // 404: either the branch does not exist upstream or GitHub does not know
    // the local commit. The branch endpoint tells these apart.
    let branch_path = format!("/repos/{REPOSITORY}/branches/{base}");
    match get(client, config, &branch_path).await {
        Ok(branch) if branch.status == StatusCode::OK => {
            let upstream_commit = branch.body["commit"]["sha"].as_str().map(str::to_string);
            Comparison {
                status: "local_only",
                upstream_commit,
                source: Some(branch.source),
                ..Comparison::default()
            }
        }
        Ok(branch) => Comparison {
            status: "branch_not_upstream",
            source: Some(branch.source),
            ..Comparison::default()
        },
        Err(error) => unknown(Some(response.source), error),
    }
}

fn unknown(source: Option<&'static str>, error: String) -> Comparison {
    Comparison {
        status: "unknown",
        source,
        error: Some(error),
        ..Comparison::default()
    }
}

/// Branch names are inserted into the API path, both directly and inside the
/// svm query string, so only characters needing no escaping are accepted.
fn is_queryable_branch(branch: &str) -> bool {
    !branch.is_empty()
        && !branch.contains("..")
        && !branch.starts_with('/')
        && branch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._/-".contains(&byte))
}

fn parse_comparison(body: &Value, source: &'static str) -> Comparison {
    let status = match body["status"].as_str() {
        Some("identical") => "identical",
        Some("ahead") => "ahead",
        Some("behind") => "behind",
        Some("diverged") => "diverged",
        other => {
            return unknown(
                Some(source),
                format!("GitHub compare returned an unexpected status: {other:?}"),
            )
        }
    };
    Comparison {
        status,
        ahead_by: body["ahead_by"].as_u64(),
        behind_by: body["behind_by"].as_u64(),
        upstream_commit: body["base_commit"]["sha"].as_str().map(str::to_string),
        source: Some(source),
        error: None,
    }
}

/// svm first; GitHub directly when svm fails or returns anything other than a
/// non-empty 200 response, mirroring Saltbox's `github_api_request.yml`. A 404
/// is returned as a response rather than an error.
async fn get(client: &Client, config: ApiConfig<'_>, path: &str) -> Result<Response, String> {
    let api_url = format!("{}{path}", config.api_base);
    let svm_url = format!("{}{api_url}", config.svm_prefix);
    let (svm_status, svm_error) = match fetch(client, &svm_url, config.request_timeout).await {
        Ok((StatusCode::OK, Some(body))) => {
            return Ok(Response {
                status: StatusCode::OK,
                body,
                source: "svm",
            })
        }
        Ok((status, _)) => (Some(status), format!("svm returned HTTP {status}")),
        Err(error) => (None, format!("svm: {error}")),
    };
    let svm_not_found = svm_status == Some(StatusCode::NOT_FOUND);

    match fetch(client, &api_url, config.request_timeout).await {
        Ok((StatusCode::OK, Some(body))) => Ok(Response {
            status: StatusCode::OK,
            body,
            source: "github",
        }),
        Ok((StatusCode::NOT_FOUND, _)) => Ok(Response {
            status: StatusCode::NOT_FOUND,
            body: Value::Null,
            source: "github",
        }),
        // GitHub is unreachable but svm already relayed GitHub's 404.
        Err(_) if svm_not_found => Ok(Response {
            status: StatusCode::NOT_FOUND,
            body: Value::Null,
            source: "svm",
        }),
        Ok((status, _)) => Err(format!("{svm_error}; GitHub returned HTTP {status}")),
        Err(error) => Err(format!("{svm_error}; GitHub: {error}")),
    }
}

/// Returns the status and, for 200 responses, the parsed JSON body (`None`
/// when the body was empty).
async fn fetch(
    client: &Client,
    url: &str,
    request_timeout: Duration,
) -> Result<(StatusCode, Option<Value>), String> {
    let display_url = url.split('?').next().unwrap_or(url);
    tokio::time::timeout(request_timeout, async {
        let response = client
            .get(url)
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .header("User-Agent", USER_AGENT)
            .send()
            .await
            .map_err(|error| format!("request to {display_url} failed: {error}"))?;
        let status = response.status();
        if status != StatusCode::OK {
            return Ok((status, None));
        }
        if response.content_length().unwrap_or_default() > MAX_RESPONSE_BYTES as u64 {
            return Err(format!(
                "response from {display_url} exceeded {MAX_RESPONSE_BYTES} bytes"
            ));
        }
        let mut body = response.bytes_stream();
        let mut bytes = Vec::new();
        while let Some(chunk) = body
            .try_next()
            .await
            .map_err(|error| format!("failed to read response from {display_url}: {error}"))?
        {
            if bytes.len() + chunk.len() > MAX_RESPONSE_BYTES {
                return Err(format!(
                    "response from {display_url} exceeded {MAX_RESPONSE_BYTES} bytes"
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        if bytes.iter().all(u8::is_ascii_whitespace) {
            return Ok((status, None));
        }
        serde_json::from_slice(&bytes)
            .map(|value| (status, Some(value)))
            .map_err(|error| format!("invalid JSON from {display_url}: {error}"))
    })
    .await
    .unwrap_or_else(|_| {
        Err(format!(
            "timeout after {request_timeout:?} for {display_url}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_ip::test_support::{test_client, within_test_deadline, TestHttpServer};
    use std::sync::{Arc, Mutex};

    const LOCAL: &str = "1111111111111111111111111111111111111111";
    const UPSTREAM: &str = "2222222222222222222222222222222222222222";

    type Route = fn(&str) -> (&'static str, String);

    /// One fixture plays both svm (`/version?url=...`) and GitHub; each
    /// request target is recorded so tests can assert the fallback order.
    struct Api {
        server: TestHttpServer,
        targets: Arc<Mutex<Vec<String>>>,
        svm_prefix: String,
    }

    impl Api {
        fn start(route: Route) -> Self {
            let targets = Arc::new(Mutex::new(Vec::new()));
            let recorded = Arc::clone(&targets);
            let server = TestHttpServer::start_with_handler(move |request, _| {
                recorded.lock().unwrap().push(request.target.clone());
                let (status, body) = route(&request.target);
                request.respond(status, &body);
            });
            let svm_prefix = format!("{}/version?url=", server.url);
            Self {
                server,
                targets,
                svm_prefix,
            }
        }

        fn config(&self) -> ApiConfig<'_> {
            ApiConfig {
                svm_prefix: &self.svm_prefix,
                api_base: &self.server.url,
                request_timeout: Duration::from_secs(5),
            }
        }

        fn targets(&self) -> Vec<String> {
            let prefix = format!("/version?url={}", self.server.url);
            self.targets
                .lock()
                .unwrap()
                .iter()
                .map(|target| match target.strip_prefix(&prefix) {
                    Some(path) => format!("svm {path}"),
                    None => format!("github {target}"),
                })
                .collect()
        }

        async fn compare(&self, base: &str) -> Comparison {
            within_test_deadline(compare(&test_client(), self.config(), base, LOCAL)).await
        }
    }

    fn compare_body(status: &str, ahead: u64, behind: u64) -> String {
        format!(
            r#"{{"status":"{status}","ahead_by":{ahead},"behind_by":{behind},"base_commit":{{"sha":"{UPSTREAM}"}},"commits":[]}}"#
        )
    }

    #[tokio::test]
    async fn reports_comparison_from_svm() {
        let api = Api::start(|target| {
            assert!(target.starts_with("/version?url="), "{target}");
            ("200 OK", compare_body("behind", 0, 3))
        });
        let result = api.compare("master").await;
        assert_eq!(
            result,
            Comparison {
                status: "behind",
                ahead_by: Some(0),
                behind_by: Some(3),
                upstream_commit: Some(UPSTREAM.to_string()),
                source: Some("svm"),
                error: None,
            }
        );
        assert_eq!(
            api.targets(),
            [format!(
                "svm /repos/saltyorg/Saltbox/compare/master...{LOCAL}?per_page=1"
            )]
        );
    }

    fn svm_error_then_github(target: &str) -> (&'static str, String) {
        if target.starts_with("/version") {
            ("500 Internal Server Error", "{}".to_string())
        } else {
            ("200 OK", compare_body("identical", 0, 0))
        }
    }

    fn svm_empty_then_github(target: &str) -> (&'static str, String) {
        if target.starts_with("/version") {
            ("200 OK", String::new())
        } else {
            ("200 OK", compare_body("identical", 0, 0))
        }
    }

    #[tokio::test]
    async fn falls_back_to_github_when_svm_fails_or_is_empty() {
        for route in [svm_error_then_github as Route, svm_empty_then_github] {
            let api = Api::start(route);
            let result = api.compare("master").await;
            assert_eq!(result.status, "identical");
            assert_eq!(result.source, Some("github"));
            assert_eq!(api.targets().len(), 2);
        }
    }

    #[tokio::test]
    async fn trusts_a_relayed_404_when_github_is_unreachable() {
        let api = Api::start(|_| ("404 Not Found", "{}".to_string()));
        let config = ApiConfig {
            api_base: "http://127.0.0.1:9",
            ..api.config()
        };
        let result = within_test_deadline(get(&test_client(), config, "/x")).await;
        assert_eq!(result.unwrap().status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn distinguishes_unpushed_commits_from_unknown_branches() {
        let api = Api::start(|target| {
            if target.contains("/compare/") {
                ("404 Not Found", r#"{"message":"Not Found"}"#.to_string())
            } else {
                (
                    "200 OK",
                    format!(r#"{{"name":"master","commit":{{"sha":"{UPSTREAM}"}}}}"#),
                )
            }
        });
        let result = api.compare("master").await;
        assert_eq!(result.status, "local_only");
        assert_eq!(result.upstream_commit.as_deref(), Some(UPSTREAM));
        assert_eq!(
            api.targets(),
            [
                format!("svm /repos/saltyorg/Saltbox/compare/master...{LOCAL}?per_page=1"),
                format!("github /repos/saltyorg/Saltbox/compare/master...{LOCAL}?per_page=1"),
                "svm /repos/saltyorg/Saltbox/branches/master".to_string(),
            ]
        );

        let api = Api::start(|_| ("404 Not Found", "{}".to_string()));
        let result = api.compare("feature/x").await;
        assert_eq!(result.status, "branch_not_upstream");
        assert_eq!(result.upstream_commit, None);
        assert_eq!(result.error, None);
    }

    #[tokio::test]
    async fn reports_unknown_when_both_endpoints_fail() {
        let api = Api::start(|_| ("503 Service Unavailable", "{}".to_string()));
        let result = api.compare("master").await;
        assert_eq!(result.status, "unknown");
        let error = result.error.unwrap();
        assert!(error.contains("svm returned HTTP 503"), "{error}");
        assert!(error.contains("GitHub returned HTTP 503"), "{error}");
    }

    #[tokio::test]
    async fn rejects_malformed_and_unexpected_responses() {
        let api = Api::start(|_| ("200 OK", "not json".to_string()));
        let result = api.compare("master").await;
        assert_eq!(result.status, "unknown");
        assert!(result.error.unwrap().contains("invalid JSON"));

        let api = Api::start(|_| ("200 OK", r#"{"status":"weird"}"#.to_string()));
        assert_eq!(api.compare("master").await.status, "unknown");
    }

    #[tokio::test]
    async fn refuses_branch_names_that_need_escaping() {
        let api = Api::start(|_| panic!("no request expected"));
        for branch in ["", "a b", "a..b", "/abs", "x?y", "x&y"] {
            let result = api.compare(branch).await;
            assert_eq!(result.status, "unknown", "{branch}");
        }
        assert_eq!(api.server.request_count(), 0);
    }

    #[tokio::test]
    async fn bounds_response_size() {
        let api = Api::start(|_| ("200 OK", format!("\"{}\"", "x".repeat(MAX_RESPONSE_BYTES))));
        let result = api.compare("master").await;
        assert!(result.error.unwrap().contains("exceeded"));
    }
}
