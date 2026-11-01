//! Decides whether the origin remote is the official public Saltbox
//! repository. Only that repository is ever queried; any other remote is
//! reported as unsupported.

const OFFICIAL_URL: &str = "https://github.com/saltyorg/saltbox";

#[derive(Debug, Eq, PartialEq)]
pub struct Remote {
    pub official: bool,
    /// The URL with any embedded credentials removed.
    pub redacted_url: Option<String>,
}

pub fn classify_remote(url: Option<&str>) -> Remote {
    let Some(url) = url.map(str::trim).filter(|url| !url.is_empty()) else {
        return Remote {
            official: false,
            redacted_url: None,
        };
    };
    let redacted = redact(url);
    Remote {
        official: is_official(&redacted),
        redacted_url: Some(redacted),
    }
}

/// `https://github.com/saltyorg/Saltbox`, ignoring case, a trailing slash,
/// and a `.git` suffix.
fn is_official(url: &str) -> bool {
    let url = url.trim_end_matches('/');
    let url = url.strip_suffix(".git").unwrap_or(url);
    url.eq_ignore_ascii_case(OFFICIAL_URL)
}

/// Removes `user[:password]@` from URLs, which can hold access tokens.
fn redact(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };
    let authority_end = rest.find('/').unwrap_or(rest.len());
    match rest[..authority_end].rfind('@') {
        Some(at) => format!("{scheme}://{}", &rest[at + 1..]),
        None => url.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn official(url: &str) -> bool {
        classify_remote(Some(url)).official
    }

    #[test]
    fn recognises_the_official_public_url() {
        for url in [
            "https://github.com/saltyorg/Saltbox.git",
            "https://github.com/saltyorg/saltbox",
            "https://github.com/saltyorg/saltbox/",
            "https://GitHub.com/SaltyOrg/Saltbox.git",
            "https://token@github.com/saltyorg/Saltbox.git",
        ] {
            assert!(official(url), "{url}");
        }
    }

    #[test]
    fn everything_else_is_unofficial() {
        for url in [
            "https://github.com/someone/Saltbox.git",
            "https://github.com/saltyorg/sb",
            "git@github.com:saltyorg/Saltbox.git",
            "https://gitlab.com/saltyorg/Saltbox.git",
            "https://github.com/saltyorg/Saltbox/tree",
            "/srv/mirror/saltbox.git",
        ] {
            assert!(!official(url), "{url}");
        }
        assert_eq!(
            classify_remote(None),
            Remote {
                official: false,
                redacted_url: None
            }
        );
    }

    #[test]
    fn removes_credentials_from_reported_urls() {
        for url in [
            "https://user:secret@github.com/saltyorg/Saltbox.git",
            "https://ghp_token@github.com/saltyorg/Saltbox.git",
        ] {
            assert_eq!(
                classify_remote(Some(url)).redacted_url.as_deref(),
                Some("https://github.com/saltyorg/Saltbox.git")
            );
        }
    }
}
