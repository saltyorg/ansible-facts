//! UFW enforcement detection without running `ufw` or `iptables`.
//!
//! `ufw status` (ufw `backend_iptables.py`, `get_status`) reports
//! "Status: inactive" when `iptables -L ufw-user-<direction> -n` cannot find
//! one of the input, output, or forward chains in the `filter` table, and it
//! additionally requires the `ufw6-user-*` chains when its IPv6 support is on.
//! It never consults `ENABLED=` in `ufw.conf` or the `ufw.service` state.
//! This module applies the same chain criterion by reading the kernel ruleset
//! directly, through the same backend `/usr/sbin/iptables` resolves to.

mod legacy;
mod nft;

use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const DIRECTIONS: [&str; 3] = ["input", "output", "forward"];

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct UfwData {
    /// Whether the ufw chains are loaded; `null` when the ruleset could not
    /// be read.
    pub active: Option<bool>,
    /// The iptables backend ufw uses: `nftables` or `legacy`.
    pub backend: Option<&'static str>,
    pub error: Option<String>,
    pub installed: bool,
}

pub struct UfwPaths {
    pub ufw: PathBuf,
    pub iptables: PathBuf,
    pub defaults: PathBuf,
    pub ipv6_sysctl: PathBuf,
    pub ip_tables_names: PathBuf,
    pub ip6_tables_names: PathBuf,
}

impl Default for UfwPaths {
    fn default() -> Self {
        Self {
            ufw: PathBuf::from("/usr/sbin/ufw"),
            iptables: PathBuf::from("/usr/sbin/iptables"),
            defaults: PathBuf::from("/etc/default/ufw"),
            ipv6_sysctl: PathBuf::from("/proc/sys/net/ipv6"),
            ip_tables_names: PathBuf::from("/proc/net/ip_tables_names"),
            ip6_tables_names: PathBuf::from("/proc/net/ip6_tables_names"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Backend {
    Nftables,
    Legacy,
}

impl Backend {
    fn label(self) -> &'static str {
        match self {
            Self::Nftables => "nftables",
            Self::Legacy => "legacy",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    Ipv4,
    Ipv6,
}

impl Family {
    fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }

    fn chain_prefix(self) -> &'static str {
        match self {
            Self::Ipv4 => "ufw-user-",
            Self::Ipv6 => "ufw6-user-",
        }
    }
}

pub fn get_ufw(paths: &UfwPaths) -> UfwData {
    get_ufw_with(paths, |backend, family| match backend {
        Backend::Nftables => nft::filter_chains(family),
        Backend::Legacy => {
            let names = match family {
                Family::Ipv4 => &paths.ip_tables_names,
                Family::Ipv6 => &paths.ip6_tables_names,
            };
            legacy::filter_chains(family, names)
        }
    })
}

/// `list_chains` returns the chain names of the `filter` table for a backend
/// and family; injecting it keeps the decision logic testable without root.
fn get_ufw_with<F>(paths: &UfwPaths, list_chains: F) -> UfwData
where
    F: Fn(Backend, Family) -> Result<BTreeSet<String>, String>,
{
    if !paths.ufw.exists() {
        return UfwData {
            active: Some(false),
            backend: None,
            error: None,
            installed: false,
        };
    }

    let backend = match detect_backend(&paths.iptables) {
        Ok(backend) => backend,
        Err(error) => {
            return UfwData {
                active: None,
                backend: None,
                error: Some(error),
                installed: true,
            }
        }
    };

    let ipv4 = list_chains(backend, Family::Ipv4);
    let ipv6 = ufw_uses_ipv6(&paths.defaults, &paths.ipv6_sysctl)
        .then(|| list_chains(backend, Family::Ipv6));
    let (active, error) = evaluate(ipv4, ipv6);
    UfwData {
        active,
        backend: Some(backend.label()),
        error,
        installed: true,
    }
}

/// Resolve the backend the way ufw does: it executes `/usr/sbin/iptables`,
/// which Debian alternatives point at either xtables multi-call binary.
fn detect_backend(iptables: &Path) -> Result<Backend, String> {
    let target = std::fs::canonicalize(iptables)
        .map_err(|error| format!("Failed to resolve {}: {error}", iptables.display()))?;
    let name = target
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    if name.contains("legacy") {
        Ok(Backend::Legacy)
    } else if name.contains("nft") {
        Ok(Backend::Nftables)
    } else {
        Err(format!(
            "Unrecognised iptables backend {} for {}",
            target.display(),
            iptables.display()
        ))
    }
}

/// ufw's `use_ipv6`: `IPV6=yes` in /etc/default/ufw and kernel IPv6 support.
fn ufw_uses_ipv6(defaults: &Path, ipv6_sysctl: &Path) -> bool {
    let enabled = std::fs::read_to_string(defaults)
        .map(|content| ipv6_enabled_in_defaults(&content))
        .unwrap_or(false);
    enabled && ipv6_sysctl.exists()
}

fn ipv6_enabled_in_defaults(content: &str) -> bool {
    content
        .lines()
        .filter_map(|line| line.trim().split_once('='))
        .rfind(|(key, _)| key.trim() == "IPV6")
        .is_some_and(|(_, value)| {
            value
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .eq_ignore_ascii_case("yes")
        })
}

fn has_ufw_chains(chains: &BTreeSet<String>, family: Family) -> bool {
    DIRECTIONS
        .iter()
        .all(|direction| chains.contains(&format!("{}{direction}", family.chain_prefix())))
}

fn evaluate(
    ipv4: Result<BTreeSet<String>, String>,
    ipv6: Option<Result<BTreeSet<String>, String>>,
) -> (Option<bool>, Option<String>) {
    let ipv4 = match ipv4 {
        Ok(chains) => chains,
        Err(error) => return (None, Some(error)),
    };
    if !has_ufw_chains(&ipv4, Family::Ipv4) {
        return (Some(false), None);
    }
    // The IPv4 firewall is enforcing at this point. ufw itself errors when the
    // IPv6 chains are then unavailable, so surface that without hiding the
    // enforcement Saltbox needs to know about.
    let warning = match ipv6 {
        None => None,
        Some(Err(error)) => Some(error),
        Some(Ok(chains)) if !has_ufw_chains(&chains, Family::Ipv6) => Some(
            "ufw IPv4 chains are loaded but its IPv6 chains are missing although IPv6 is enabled"
                .to_string(),
        ),
        Some(Ok(_)) => None,
    };
    (Some(true), warning)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    fn chains(family: Family, directions: &[&str]) -> BTreeSet<String> {
        directions
            .iter()
            .map(|direction| format!("{}{direction}", family.chain_prefix()))
            .chain(["DOCKER".to_string(), "INPUT".to_string()])
            .collect()
    }

    fn all(family: Family) -> BTreeSet<String> {
        chains(family, &DIRECTIONS)
    }

    struct Fixture {
        directory: TempDir,
        paths: UfwPaths,
    }

    impl Fixture {
        fn new(iptables_target: &str, ipv6: Option<&str>) -> Self {
            let directory = tempfile::tempdir().unwrap();
            let root = directory.path();
            let paths = UfwPaths {
                ufw: root.join("ufw"),
                iptables: root.join("iptables"),
                defaults: root.join("default-ufw"),
                ipv6_sysctl: root.join("ipv6"),
                ip_tables_names: root.join("ip_tables_names"),
                ip6_tables_names: root.join("ip6_tables_names"),
            };
            std::fs::write(&paths.ufw, "").unwrap();
            let target = root.join(iptables_target);
            std::fs::write(&target, "").unwrap();
            symlink(&target, &paths.iptables).unwrap();
            std::fs::create_dir(&paths.ipv6_sysctl).unwrap();
            if let Some(value) = ipv6 {
                std::fs::write(&paths.defaults, format!("# comment\nIPV6={value}\n")).unwrap();
            }
            Self { directory, paths }
        }
    }

    #[test]
    fn absent_ufw_is_inactive_and_reads_nothing() {
        let fixture = Fixture::new("xtables-nft-multi", Some("yes"));
        std::fs::remove_file(&fixture.paths.ufw).unwrap();
        let data = get_ufw_with(&fixture.paths, |_, _| panic!("ruleset was read"));
        assert_eq!(
            data,
            UfwData {
                active: Some(false),
                backend: None,
                error: None,
                installed: false,
            }
        );
    }

    #[test]
    fn follows_the_iptables_alternative() {
        for (target, expected) in [
            ("xtables-nft-multi", Backend::Nftables),
            ("xtables-legacy-multi", Backend::Legacy),
        ] {
            let fixture = Fixture::new(target, Some("no"));
            let seen = RefCell::new(Vec::new());
            let data = get_ufw_with(&fixture.paths, |backend, family| {
                seen.borrow_mut().push((backend, family));
                Ok(all(family))
            });
            assert_eq!(data.backend, Some(expected.label()));
            assert_eq!(*seen.borrow(), [(expected, Family::Ipv4)]);
        }
    }

    #[test]
    fn unknown_backend_is_reported() {
        let fixture = Fixture::new("something-else", Some("yes"));
        let data = get_ufw_with(&fixture.paths, |_, _| panic!("ruleset was read"));
        assert_eq!(data.active, None);
        assert!(data
            .error
            .unwrap()
            .contains("Unrecognised iptables backend"));
    }

    #[test]
    fn active_requires_every_direction() {
        let fixture = Fixture::new("xtables-nft-multi", Some("no"));
        let data = get_ufw_with(&fixture.paths, |_, family| Ok(all(family)));
        assert_eq!((data.active, data.error), (Some(true), None));

        let data = get_ufw_with(&fixture.paths, |_, family| {
            Ok(chains(family, &["input", "output"]))
        });
        assert_eq!((data.active, data.error), (Some(false), None));
    }

    #[test]
    fn checks_ipv6_chains_only_when_ufw_uses_ipv6() {
        let fixture = Fixture::new("xtables-nft-multi", Some("yes"));
        let data = get_ufw_with(&fixture.paths, |_, family| Ok(all(family)));
        assert_eq!((data.active, data.error), (Some(true), None));

        let data = get_ufw_with(&fixture.paths, |_, family| match family {
            Family::Ipv4 => Ok(all(family)),
            Family::Ipv6 => Ok(BTreeSet::new()),
        });
        assert_eq!(data.active, Some(true));
        assert!(data.error.unwrap().contains("IPv6 chains are missing"));

        std::fs::remove_dir(&fixture.paths.ipv6_sysctl).unwrap();
        let data = get_ufw_with(&fixture.paths, |_, family| match family {
            Family::Ipv4 => Ok(all(family)),
            Family::Ipv6 => panic!("IPv6 ruleset was read without kernel IPv6"),
        });
        assert_eq!((data.active, data.error), (Some(true), None));
    }

    #[test]
    fn unreadable_ruleset_is_unknown() {
        let fixture = Fixture::new("xtables-nft-multi", None);
        let data = get_ufw_with(&fixture.paths, |_, _| {
            Err("Operation not permitted".to_string())
        });
        assert_eq!(data.active, None);
        assert_eq!(data.error.as_deref(), Some("Operation not permitted"));
        drop(fixture.directory);
    }

    #[test]
    fn parses_ipv6_setting_like_ufw_defaults() {
        assert!(ipv6_enabled_in_defaults("IPV6=yes\n"));
        assert!(ipv6_enabled_in_defaults("IPV6=\"yes\"\n"));
        assert!(!ipv6_enabled_in_defaults("IPV6=no\n"));
        assert!(!ipv6_enabled_in_defaults("#IPV6=yes\n"));
        assert!(!ipv6_enabled_in_defaults(""));
        assert!(ipv6_enabled_in_defaults("IPV6=no\nIPV6=yes\n"));
    }
}
