mod address;
mod cache;
mod http;

use address::AddressFamily;
use reqwest::Client;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LookupOutcome {
    pub address: Option<String>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicIpResolution {
    pub ipv4: LookupOutcome,
    pub ipv6: LookupOutcome,
    pub cache_warning: Option<String>,
}

#[derive(Clone, Copy)]
struct LookupPolicy<'a> {
    cache_path: &'a Path,
    observed_at: u64,
    reload_validation_clock: CacheValidationClock,
    retry_delays: [Duration; 2],
    request_timeout: Duration,
    cache_lock_timeout: Duration,
}

#[derive(Clone, Copy)]
enum CacheValidationClock {
    System,
    #[cfg(test)]
    Fixed(u64),
    #[cfg(test)]
    CheckWorkerThread {
        now: u64,
        executor: std::thread::ThreadId,
    },
}

impl CacheValidationClock {
    fn sample(self) -> u64 {
        match self {
            Self::System => SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            #[cfg(test)]
            Self::Fixed(now) => now,
            #[cfg(test)]
            Self::CheckWorkerThread { now, executor } => {
                assert_ne!(
                    std::thread::current().id(),
                    executor,
                    "cache persistence ran on the async executor thread"
                );
                now
            }
        }
    }
}

struct LookupExecution {
    outcome: LookupOutcome,
    live_address: Option<String>,
}

pub async fn resolve_public_ips(
    client: &Client,
    ipv4_urls: &[&str],
    ipv6_urls: &[&str],
    ipv6_available: bool,
    ipv6_unavailable_error: String,
) -> PublicIpResolution {
    let validation_clock = CacheValidationClock::System;
    let observed_at = validation_clock.sample();
    resolve_public_ips_with_policy(
        client,
        ipv4_urls,
        ipv6_urls,
        ipv6_available,
        ipv6_unavailable_error,
        LookupPolicy {
            cache_path: Path::new(cache::PUBLIC_IP_CACHE_PATH),
            observed_at,
            reload_validation_clock: validation_clock,
            retry_delays: http::RETRY_DELAYS,
            request_timeout: http::REQUEST_TIMEOUT,
            cache_lock_timeout: cache::CACHE_LOCK_TIMEOUT,
        },
    )
    .await
}

async fn resolve_public_ips_with_policy(
    client: &Client,
    ipv4_urls: &[&str],
    ipv6_urls: &[&str],
    ipv6_available: bool,
    ipv6_unavailable_error: String,
    policy: LookupPolicy<'_>,
) -> PublicIpResolution {
    let cache_path = policy.cache_path.to_path_buf();
    let (loaded_cache, mut cache_read_warnings) =
        match tokio::task::spawn_blocking(move || cache::load(&cache_path, policy.observed_at))
            .await
        {
            Ok(result) => (result.cache, result.warnings),
            Err(error) => (None, vec![format!("cache read task failed: {error}")]),
        };
    let cached_ipv4 = loaded_cache
        .as_ref()
        .and_then(|cache| cache::fresh_address(cache, AddressFamily::Ipv4, policy.observed_at));
    let cached_ipv6 = if ipv6_available {
        loaded_cache
            .as_ref()
            .and_then(|cache| cache::fresh_address(cache, AddressFamily::Ipv6, policy.observed_at))
    } else {
        None
    };

    let ipv4_future = resolve_family(client, ipv4_urls, cached_ipv4, AddressFamily::Ipv4, policy);
    let ipv6_future = async {
        if !ipv6_available {
            return LookupExecution {
                outcome: LookupOutcome {
                    address: None,
                    error: Some(ipv6_unavailable_error),
                },
                live_address: None,
            };
        }
        resolve_family(client, ipv6_urls, cached_ipv6, AddressFamily::Ipv6, policy).await
    };

    let (ipv4, ipv6) = tokio::join!(ipv4_future, ipv6_future);

    let cache_write_warning = if ipv4.live_address.is_some() || ipv6.live_address.is_some() {
        let cache_path = policy.cache_path.to_path_buf();
        let live_ipv4 = ipv4.live_address;
        let live_ipv6 = ipv6.live_address;
        let reload_validation_clock = policy.reload_validation_clock;
        match tokio::task::spawn_blocking(move || {
            cache::merge_successful_entries_with_timeout(
                &cache_path,
                live_ipv4,
                live_ipv6,
                policy.observed_at,
                || reload_validation_clock.sample(),
                policy.cache_lock_timeout,
            )
        })
        .await
        {
            Ok(result) => {
                for warning in result.read_warnings {
                    if !cache_read_warnings.contains(&warning) {
                        cache_read_warnings.push(warning);
                    }
                }
                result.write_result.err().map(|error| error.to_string())
            }
            Err(error) => Some(format!("cache write task failed: {error}")),
        }
    } else {
        None
    };

    PublicIpResolution {
        ipv4: ipv4.outcome,
        ipv6: ipv6.outcome,
        cache_warning: aggregate_cache_warnings(cache_read_warnings, cache_write_warning),
    }
}

fn aggregate_cache_warnings(
    cache_read_warnings: Vec<String>,
    cache_write_warning: Option<String>,
) -> Option<String> {
    let mut phases = Vec::with_capacity(2);
    if !cache_read_warnings.is_empty() {
        phases.push(format!(
            "cache read ignored: {}",
            cache_read_warnings.join("; ")
        ));
    }
    if let Some(warning) = cache_write_warning {
        phases.push(format!("cache write skipped: {warning}"));
    }
    (!phases.is_empty()).then(|| phases.join(" | "))
}

async fn resolve_family(
    client: &Client,
    urls: &[&str],
    cached_address: Option<String>,
    family: AddressFamily,
    policy: LookupPolicy<'_>,
) -> LookupExecution {
    match cached_address {
        Some(address) => LookupExecution {
            outcome: LookupOutcome {
                address: Some(address),
                error: None,
            },
            live_address: None,
        },
        None => {
            let outcome = http::lookup_with_retry(
                client,
                urls,
                family,
                policy.retry_delays,
                policy.request_timeout,
            )
            .await;
            let live_address = outcome.address.clone();
            LookupExecution {
                outcome,
                live_address,
            }
        }
    }
}

pub fn has_valid_ipv6(file_path: &str) -> (bool, Option<String>) {
    match std::fs::read_to_string(file_path) {
        Ok(content) => (has_global_ipv6_from_if_inet6(&content), None),
        Err(error) => (false, Some(format!("Error checking IPv6: {error}"))),
    }
}

pub fn ipv6_unavailable_error(check_error: Option<&str>) -> String {
    check_error
        .unwrap_or("No global IPv6 address was detected on a local interface")
        .to_string()
}

pub fn has_global_ipv6_from_if_inet6(content: &str) -> bool {
    for line in content.lines() {
        let mut fields = line.split_whitespace();
        let (Some(_), Some(_), Some(_), Some(scope), Some(_), Some(_)) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        ) else {
            continue;
        };
        if scope == "00" {
            return true;
        }
    }
    false
}

#[cfg(test)]
pub(super) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_global_ipv6_address_from_if_inet6_data() {
        let content = "\
fe800000000000000000000000000001 02 40 20 80 eth0
2a0104f9c014e6d90000000000000001 02 40 00 80 eth0
";
        assert!(has_global_ipv6_from_if_inet6(content));
    }

    #[test]
    fn returns_false_when_only_link_local_ipv6_addresses_exist() {
        let content = "\
fe800000000000000000000000000001 02 40 20 80 eth0
fe800000000000000000000000000002 03 40 20 80 eth1
";
        assert!(!has_global_ipv6_from_if_inet6(content));
    }

    #[test]
    fn ignores_malformed_if_inet6_lines() {
        assert!(!has_global_ipv6_from_if_inet6("not enough fields\n1234\n"));
    }

    #[test]
    fn explains_why_ipv6_was_not_attempted() {
        assert_eq!(
            ipv6_unavailable_error(None),
            "No global IPv6 address was detected on a local interface"
        );
        assert_eq!(
            ipv6_unavailable_error(Some("Error checking IPv6: unavailable")),
            "Error checking IPv6: unavailable"
        );
    }
}
