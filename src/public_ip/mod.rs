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
    now: u64,
    retry_delays: [Duration; 2],
    request_timeout: Duration,
    cache_lock_timeout: Duration,
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
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    resolve_public_ips_with_policy(
        client,
        ipv4_urls,
        ipv6_urls,
        ipv6_available,
        ipv6_unavailable_error,
        LookupPolicy {
            cache_path: Path::new(cache::PUBLIC_IP_CACHE_PATH),
            now,
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
    let loaded_cache = tokio::task::spawn_blocking(move || cache::load(&cache_path))
        .await
        .ok()
        .flatten();
    let cached_ipv4 = loaded_cache
        .as_ref()
        .and_then(|cache| cache::fresh_address(cache, AddressFamily::Ipv4, policy.now));
    let cached_ipv6 = if ipv6_available {
        loaded_cache
            .as_ref()
            .and_then(|cache| cache::fresh_address(cache, AddressFamily::Ipv6, policy.now))
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

    if ipv4.live_address.is_some() || ipv6.live_address.is_some() {
        let cache_path = policy.cache_path.to_path_buf();
        let live_ipv4 = ipv4.live_address;
        let live_ipv6 = ipv6.live_address;
        let _ = tokio::task::spawn_blocking(move || {
            cache::merge_successful_entries_with_timeout(
                &cache_path,
                live_ipv4,
                live_ipv6,
                policy.now,
                policy.cache_lock_timeout,
            )
        })
        .await;
    }

    PublicIpResolution {
        ipv4: ipv4.outcome,
        ipv6: ipv6.outcome,
        cache_warning: None,
    }
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
pub(super) mod test_support {
    use super::LookupPolicy;
    use std::fs;
    use std::io::{self, BufRead, BufReader as StdBufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use tempfile::TempDir;

    pub(super) struct TestDirectory {
        directory: TempDir,
    }

    impl TestDirectory {
        pub(super) fn new() -> Self {
            let directory = tempfile::Builder::new()
                .prefix("saltbox-facts-test-")
                .tempdir()
                .unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            Self { directory }
        }

        pub(super) fn path(&self) -> &Path {
            self.directory.path()
        }

        pub(super) fn cache_path(&self) -> PathBuf {
            let namespace = self.path().join("saltbox");
            let cache_directory = namespace.join("facts");
            if !namespace.exists() {
                fs::create_dir(&namespace).unwrap();
            }
            if !cache_directory.exists() {
                fs::create_dir(&cache_directory).unwrap();
            }
            fs::set_permissions(&namespace, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&cache_directory, fs::Permissions::from_mode(0o700)).unwrap();
            cache_directory.join("public-ip.json")
        }
    }

    pub(super) fn write_private_cache(path: &Path, contents: impl AsRef<[u8]>) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    pub(super) struct TestHttpServer {
        pub(super) url: String,
        requests: Arc<AtomicUsize>,
        shutdown: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl TestHttpServer {
        pub(super) fn start<F>(response: F) -> Self
        where
            F: Fn(usize) -> (&'static str, &'static str, Duration) + Send + Sync + 'static,
        {
            Self::start_with_handler(move |stream, request_number| {
                handle_test_request(stream, response(request_number));
            })
        }

        pub(super) fn start_with_handler<F>(handler: F) -> Self
        where
            F: Fn(TcpStream, usize) + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(AtomicUsize::new(0));
            let shutdown = Arc::new(AtomicBool::new(false));
            let thread_requests = Arc::clone(&requests);
            let thread_shutdown = Arc::clone(&shutdown);
            let handler = Arc::new(handler);
            let server_thread = thread::spawn(move || {
                while !thread_shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let request_number = thread_requests.fetch_add(1, Ordering::SeqCst) + 1;
                            handler(stream, request_number);
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(1));
                        }
                        Err(error) => panic!("test server accept failed: {error}"),
                    }
                }
            });

            Self {
                url: format!("http://{address}"),
                requests,
                shutdown,
                thread: Some(server_thread),
            }
        }

        pub(super) fn request_count(&self) -> usize {
            self.requests.load(Ordering::SeqCst)
        }
    }

    impl Drop for TestHttpServer {
        fn drop(&mut self) {
            self.shutdown.store(true, Ordering::SeqCst);
            if let Some(thread) = self.thread.take() {
                thread.join().unwrap();
            }
        }
    }

    pub(super) fn handle_test_request(
        mut stream: TcpStream,
        (status, body, delay): (&str, &str, Duration),
    ) {
        let mut reader = StdBufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }
        thread::sleep(delay);
        if let Err(error) = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ) {
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        }
    }

    pub(super) fn handle_raw_test_request(
        mut stream: TcpStream,
        status: &str,
        headers: &[(&str, &str)],
        body_chunks: &[&[u8]],
        delay: Duration,
    ) {
        let mut reader = StdBufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }
        thread::sleep(delay);
        write!(stream, "HTTP/1.1 {status}\r\nConnection: close\r\n").unwrap();
        for (name, value) in headers {
            write!(stream, "{name}: {value}\r\n").unwrap();
        }
        write!(stream, "\r\n").unwrap();

        let chunked = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Transfer-Encoding") && *value == "chunked"
        });
        for chunk in body_chunks {
            if chunked {
                write!(stream, "{:X}\r\n", chunk.len()).unwrap();
            }
            stream.write_all(chunk).unwrap();
            if chunked {
                stream.write_all(b"\r\n").unwrap();
            }
        }
        if chunked {
            stream.write_all(b"0\r\n\r\n").unwrap();
        }
    }

    pub(super) fn server_urls(servers: &[&TestHttpServer]) -> Vec<String> {
        servers.iter().map(|server| server.url.clone()).collect()
    }

    pub(super) fn url_refs(urls: &[String]) -> Vec<&str> {
        urls.iter().map(String::as_str).collect()
    }

    pub(super) fn test_lookup_policy(cache_path: &Path, now: u64) -> LookupPolicy<'_> {
        LookupPolicy {
            cache_path,
            now,
            retry_delays: [Duration::ZERO, Duration::ZERO],
            request_timeout: Duration::from_millis(25),
            cache_lock_timeout: Duration::from_millis(25),
        }
    }
}

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
