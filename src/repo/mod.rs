//! Saltbox repository status: the local checkout compared with official
//! Saltbox. Non-official remotes are reported as unsupported without any
//! network request.

mod git;
mod github;
mod remote;

pub use github::ApiConfig;

use git::LocalState;
use remote::classify_remote;
use reqwest::Client;
use serde::Serialize;
use std::path::{Path, PathBuf};

pub const SALTBOX_REPO_PATH: &str = "/srv/git/saltbox";
const FACTS_DIRECTORY_NAME: &str = "ansible_facts.d";
/// Compared against when HEAD is detached; Saltbox's default branch.
const DEFAULT_BRANCH: &str = "master";

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct RepoData {
    pub ahead_by: Option<u64>,
    pub behind_by: Option<u64>,
    pub branch: Option<String>,
    pub commit: Option<String>,
    pub detached: bool,
    pub error: Option<String>,
    /// Whether origin is the official public Saltbox repository; only then
    /// is the upstream status queried.
    pub official: bool,
    pub path: String,
    pub remote_url: Option<String>,
    pub source: Option<&'static str>,
    /// `identical`, `behind`, `ahead`, `diverged`, `local_only`,
    /// `branch_not_upstream`, `unsupported`, or `unknown`.
    pub status: &'static str,
    pub upstream_commit: Option<String>,
}

/// The fact describes the repository that contains its `ansible_facts.d`
/// directory, which also covers CI checkouts outside /srv/git/saltbox.
pub fn locate_repo(executable: Option<&Path>) -> PathBuf {
    executable
        .and_then(Path::parent)
        .filter(|directory| {
            directory
                .file_name()
                .is_some_and(|name| name == FACTS_DIRECTORY_NAME)
        })
        .and_then(Path::parent)
        .map_or_else(|| PathBuf::from(SALTBOX_REPO_PATH), Path::to_path_buf)
}

pub async fn get_repo(client: &Client, repo: PathBuf, api: ApiConfig<'_>) -> RepoData {
    let path = repo.display().to_string();
    let local = tokio::task::spawn_blocking(move || git::read_local(&repo))
        .await
        .unwrap_or_else(|error| Err(format!("Git read task failed: {error}")));
    let local = match local {
        Ok(local) => local,
        Err(error) => {
            return RepoData {
                ahead_by: None,
                behind_by: None,
                branch: None,
                commit: None,
                detached: false,
                error: Some(error),
                official: false,
                path,
                remote_url: None,
                source: None,
                status: "unknown",
                upstream_commit: None,
            }
        }
    };
    let remote = classify_remote(local.origin_url.as_deref());
    let LocalState {
        branch,
        commit,
        detached,
        ..
    } = local;
    let mut data = RepoData {
        ahead_by: None,
        behind_by: None,
        branch,
        commit,
        detached,
        error: None,
        official: remote.official,
        path,
        remote_url: remote.redacted_url,
        source: None,
        status: "unknown",
        upstream_commit: None,
    };

    if !remote.official {
        data.status = "unsupported";
        return data;
    }
    let Some(commit) = data.commit.as_deref() else {
        data.error = Some("The checked-out branch has no commits".to_string());
        return data;
    };
    if commit.len() != 40 {
        data.error = Some("SHA-256 repositories cannot be compared with GitHub".to_string());
        return data;
    }

    let base = data.branch.as_deref().unwrap_or(DEFAULT_BRANCH);
    let comparison = github::compare(client, api, base, commit).await;
    data.status = comparison.status;
    data.ahead_by = comparison.ahead_by;
    data.behind_by = comparison.behind_by;
    data.upstream_commit = comparison.upstream_commit;
    data.source = comparison.source;
    data.error = comparison.error;
    data
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_ip::test_support::{test_client, within_test_deadline, TestHttpServer};
    use std::fs;
    use std::time::Duration;

    const SHA: &str = "1111111111111111111111111111111111111111";

    fn repo(url: Option<&str>, head: &str) -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        let git = directory.path().join(".git");
        fs::create_dir_all(git.join("refs/heads")).unwrap();
        fs::write(git.join("HEAD"), head).unwrap();
        fs::write(git.join("refs/heads/master"), SHA).unwrap();
        if let Some(url) = url {
            fs::write(
                git.join("config"),
                format!("[remote \"origin\"]\n\turl = {url}\n"),
            )
            .unwrap();
        }
        directory
    }

    async fn status(repo: &Path, server: &TestHttpServer) -> RepoData {
        let svm_prefix = format!("{}/version?url=", server.url);
        let config = ApiConfig {
            svm_prefix: &svm_prefix,
            api_base: &server.url,
            request_timeout: Duration::from_secs(5),
        };
        within_test_deadline(get_repo(&test_client(), repo.to_path_buf(), config)).await
    }

    #[test]
    fn locates_the_repository_from_the_fact_path() {
        assert_eq!(
            locate_repo(Some(Path::new(
                "/home/runner/work/Saltbox/Saltbox/ansible_facts.d/saltbox.fact"
            ))),
            PathBuf::from("/home/runner/work/Saltbox/Saltbox")
        );
        assert_eq!(
            locate_repo(Some(Path::new("/usr/local/bin/saltbox-facts"))),
            PathBuf::from(SALTBOX_REPO_PATH)
        );
        assert_eq!(locate_repo(None), PathBuf::from(SALTBOX_REPO_PATH));
    }

    #[tokio::test]
    async fn compares_official_checkouts() {
        let checkout = repo(
            Some("https://x-access-token:secret@github.com/saltyorg/Saltbox.git"),
            "ref: refs/heads/master\n",
        );
        let server = TestHttpServer::start(|_| {
            (
                "200 OK",
                r#"{"status":"identical","ahead_by":0,"behind_by":0,"base_commit":{"sha":"1111111111111111111111111111111111111111"}}"#,
            )
        });
        let data = status(checkout.path(), &server).await;
        assert_eq!(
            data,
            RepoData {
                ahead_by: Some(0),
                behind_by: Some(0),
                branch: Some("master".to_string()),
                commit: Some(SHA.to_string()),
                detached: false,
                error: None,
                official: true,
                path: checkout.path().display().to_string(),
                remote_url: Some("https://github.com/saltyorg/Saltbox.git".to_string()),
                source: Some("svm"),
                status: "identical",
                upstream_commit: Some(SHA.to_string()),
            }
        );
    }

    #[tokio::test]
    async fn detached_heads_compare_against_the_default_branch() {
        let checkout = repo(Some("https://github.com/saltyorg/Saltbox.git"), SHA);
        let server = TestHttpServer::start_with_handler(|request, _| {
            assert!(
                request.target.contains("/compare/master..."),
                "{}",
                request.target
            );
            request.respond(
                "200 OK",
                r#"{"status":"behind","ahead_by":0,"behind_by":2,"base_commit":{"sha":"x"}}"#,
            );
        });
        let data = status(checkout.path(), &server).await;
        assert!(data.detached);
        assert_eq!(data.branch, None);
        assert_eq!(data.status, "behind");
    }

    #[tokio::test]
    async fn non_official_remotes_are_unsupported_without_requests() {
        let server = TestHttpServer::start(|_| panic!("no request expected"));
        for url in [
            Some("https://github.com/someone/Saltbox.git"),
            Some("https://gitlab.com/someone/saltbox"),
            None,
        ] {
            let checkout = repo(url, "ref: refs/heads/master\n");
            let data = status(checkout.path(), &server).await;
            assert_eq!(data.status, "unsupported");
            assert!(!data.official);
            assert_eq!(data.commit.as_deref(), Some(SHA));
            assert_eq!(data.error, None);
        }
        assert_eq!(server.request_count(), 0);
    }

    #[tokio::test]
    async fn local_failures_are_reported_without_requests() {
        let server = TestHttpServer::start(|_| panic!("no request expected"));
        let missing = tempfile::tempdir().unwrap();
        let data = status(missing.path(), &server).await;
        assert_eq!(data.status, "unknown");
        assert!(data.error.unwrap().contains("not a Git repository"));

        let unborn = repo(
            Some("https://github.com/saltyorg/Saltbox"),
            "ref: refs/heads/new\n",
        );
        let data = status(unborn.path(), &server).await;
        assert_eq!(data.status, "unknown");
        assert_eq!(data.branch.as_deref(), Some("new"));
        assert!(data.error.unwrap().contains("no commits"));
        assert_eq!(server.request_count(), 0);
    }
}
