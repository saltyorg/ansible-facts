use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::TryStreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
pub const PUBLIC_IP_CACHE_PATH: &str = "/srv/git/saltbox/saltbox-facts-cache.json";
const MAX_IP_RESPONSE_BYTES: u64 = 64;
const CACHE_VERSION: u8 = 1;
const CACHE_TTL_SECONDS: u64 = 900;
const MAX_CACHE_BYTES: usize = 4096;
const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
const CACHE_LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(250), Duration::from_millis(750)];
const O_NONBLOCK: i32 = 0o4000;
const O_NOFOLLOW: i32 = 0o400000;
static CACHE_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

type IpLookupResult = (Option<String>, Option<String>);

#[derive(Clone, Copy)]
struct LookupPolicy<'a> {
    cache_path: &'a Path,
    now: u64,
    retry_delays: [Duration; 2],
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheEntry {
    address: String,
    observed_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PublicIpCache {
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv4: Option<CacheEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv6: Option<CacheEntry>,
}

impl Default for PublicIpCache {
    fn default() -> Self {
        Self {
            version: CACHE_VERSION,
            ipv4: None,
            ipv6: None,
        }
    }
}

#[derive(Serialize)]
pub struct Output<'a> {
    pub saltbox_facts_version: &'a str,
    pub ip: IpOutput,
    pub groups: HashMap<String, GroupData>,
    pub users: HashMap<String, UserData>,
    pub timezone: TimezoneData,
}

#[derive(Serialize)]
pub struct IpOutput {
    pub public_ip: String,
    pub public_ipv6: String,
    pub error_ipv4: Option<String>,
    pub error_ipv6: Option<String>,
    pub failed_ipv4: bool,
    pub failed_ipv6: bool,
    pub ipv6_check_error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct GroupData {
    pub gid: String,
    #[serde(rename = "group-list")]
    pub group_list: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct UserData {
    pub uid: String,
    pub gid: String,
    pub comment: String,
    pub home: String,
    pub shell: String,
}

#[derive(Serialize)]
pub struct TimezoneData {
    pub timezone: String,
}

pub fn sort_json_value(value: serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut sorted = BTreeMap::new();
            for (key, value) in map {
                sorted.insert(key, sort_json_value(value));
            }

            let mut ordered_map = serde_json::Map::with_capacity(sorted.len());
            for (key, value) in sorted {
                ordered_map.insert(key, value);
            }
            serde_json::Value::Object(ordered_map)
        }
        serde_json::Value::Array(values) => {
            serde_json::Value::Array(values.into_iter().map(sort_json_value).collect())
        }
        other => other,
    }
}

pub async fn get_ip(
    client: &Client,
    urls: &[&str],
    is_ipv6: bool,
) -> (Option<String>, Option<String>) {
    if urls.is_empty() {
        return (
            None,
            Some("All requests failed with unknown errors".to_string()),
        );
    }

    let mut errors = Vec::new();
    let mut requests = FuturesUnordered::new();

    for &url in urls {
        requests.push(fetch_ip_from_url(client, url, is_ipv6));
    }

    while let Some(result) = requests.next().await {
        match result {
            Ok(ip) => return (Some(ip), None),
            Err(error) => errors.push(error),
        }
    }

    let combined_error = if errors.is_empty() {
        "All requests failed with unknown errors".to_string()
    } else {
        errors.join("; ")
    };

    (None, Some(combined_error))
}

async fn get_ip_with_retry(
    client: &Client,
    urls: &[&str],
    is_ipv6: bool,
    retry_delays: [Duration; 2],
) -> (Option<String>, Option<String>) {
    let mut attempt_errors = Vec::with_capacity(3);

    for attempt in 0..3 {
        let (address, error) = get_ip(client, urls, is_ipv6).await;
        if address.is_some() {
            return (address, None);
        }

        attempt_errors.push(format!(
            "Attempt {}: {}",
            attempt + 1,
            error.unwrap_or_else(|| "All requests failed with unknown errors".to_string())
        ));
        if let Some(delay) = retry_delays.get(attempt) {
            tokio::time::sleep(*delay).await;
        }
    }

    (None, Some(attempt_errors.join(" | ")))
}

pub async fn resolve_public_ips(
    client: &Client,
    ipv4_urls: &[&str],
    ipv6_urls: &[&str],
    ipv6_available: bool,
    ipv6_unavailable_error: String,
) -> (IpLookupResult, IpLookupResult) {
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
            cache_path: Path::new(PUBLIC_IP_CACHE_PATH),
            now,
            retry_delays: RETRY_DELAYS,
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
) -> (IpLookupResult, IpLookupResult) {
    let loaded_cache = load_cache(policy.cache_path);
    let cached_ipv4 = loaded_cache
        .as_ref()
        .and_then(|cache| fresh_cached_address(cache, false, policy.now));
    let cached_ipv6 = if ipv6_available {
        loaded_cache
            .as_ref()
            .and_then(|cache| fresh_cached_address(cache, true, policy.now))
    } else {
        None
    };

    let ipv4_future = async {
        match cached_ipv4 {
            Some(address) => ((Some(address), None), None),
            None => {
                let result = get_ip_with_retry(client, ipv4_urls, false, policy.retry_delays).await;
                let live_address = result.0.clone();
                (result, live_address)
            }
        }
    };
    let ipv6_future = async {
        if !ipv6_available {
            return ((None, Some(ipv6_unavailable_error)), None);
        }
        match cached_ipv6 {
            Some(address) => ((Some(address), None), None),
            None => {
                let result = get_ip_with_retry(client, ipv6_urls, true, policy.retry_delays).await;
                let live_address = result.0.clone();
                (result, live_address)
            }
        }
    };

    let ((ipv4_result, live_ipv4), (ipv6_result, live_ipv6)) =
        tokio::join!(ipv4_future, ipv6_future);

    if live_ipv4.is_some() || live_ipv6.is_some() {
        let _ = merge_successful_cache_entries(policy.cache_path, live_ipv4, live_ipv6, policy.now);
    }

    (ipv4_result, ipv6_result)
}

fn load_cache(cache_path: &Path) -> Option<PublicIpCache> {
    let cache_file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(cache_path)
        .ok()?;
    let metadata = cache_file.metadata().ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CACHE_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    cache_file
        .take(MAX_CACHE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_CACHE_BYTES {
        return None;
    }
    serde_json::from_slice(&bytes).ok()
}

fn fresh_cached_address(cache: &PublicIpCache, is_ipv6: bool, now: u64) -> Option<String> {
    if cache.version != CACHE_VERSION {
        return None;
    }
    let entry = if is_ipv6 {
        cache.ipv6.as_ref()
    } else {
        cache.ipv4.as_ref()
    }?;
    let age = now.checked_sub(entry.observed_at)?;
    (age < CACHE_TTL_SECONDS && validate_ip(&entry.address, is_ipv6)).then(|| entry.address.clone())
}

fn cache_for_update(cache: Option<PublicIpCache>) -> PublicIpCache {
    let Some(mut cache) = cache.filter(|cache| cache.version == CACHE_VERSION) else {
        return PublicIpCache::default();
    };
    cache.ipv4 = cache
        .ipv4
        .filter(|entry| validate_ip(&entry.address, false));
    cache.ipv6 = cache.ipv6.filter(|entry| validate_ip(&entry.address, true));
    cache
}

fn merge_successful_cache_entries(
    cache_path: &Path,
    live_ipv4: Option<String>,
    live_ipv6: Option<String>,
    now: u64,
) -> io::Result<()> {
    let parent = cache_path
        .parent()
        .ok_or_else(|| io::Error::other("cache path has no parent directory"))?;
    let lock_path = parent.join(".saltbox-facts-cache.lock");
    let lock_file = acquire_cache_lock(&lock_path)?;

    let mut cache = cache_for_update(load_cache(cache_path));
    if let Some(address) = live_ipv4 {
        cache.ipv4 = Some(CacheEntry {
            address,
            observed_at: now,
        });
    }
    if let Some(address) = live_ipv6 {
        cache.ipv6 = Some(CacheEntry {
            address,
            observed_at: now,
        });
    }
    write_cache_atomically(cache_path, &cache)?;
    drop(lock_file);
    Ok(())
}

fn acquire_cache_lock(lock_path: &Path) -> io::Result<File> {
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o644)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(lock_path)?;
    if !lock_file.metadata()?.file_type().is_file() {
        return Err(io::Error::other("cache lock target is not a regular file"));
    }
    lock_file.set_permissions(fs::Permissions::from_mode(0o644))?;
    let started = Instant::now();
    loop {
        match lock_file.try_lock() {
            Ok(()) => return Ok(lock_file),
            Err(TryLockError::WouldBlock) => {
                let elapsed = started.elapsed();
                if elapsed >= CACHE_LOCK_TIMEOUT {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out acquiring cache lock",
                    ));
                }
                std::thread::sleep(CACHE_LOCK_RETRY_DELAY.min(CACHE_LOCK_TIMEOUT - elapsed));
            }
            Err(TryLockError::Error(error)) => return Err(error),
        }
    }
}

fn write_cache_atomically(cache_path: &Path, cache: &PublicIpCache) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(cache_path) {
        if !metadata.file_type().is_file() {
            return Err(io::Error::other("cache target is not a regular file"));
        }
    }

    let parent = cache_path
        .parent()
        .ok_or_else(|| io::Error::other("cache path has no parent directory"))?;
    let temp_path = unique_cache_temp_path(parent);
    let result = (|| {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&temp_path)?;
        serde_json::to_writer(&mut temp, cache).map_err(io::Error::other)?;
        temp.write_all(b"\n")?;
        temp.set_permissions(fs::Permissions::from_mode(0o644))?;
        temp.sync_all()?;

        match fs::symlink_metadata(cache_path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(io::Error::other("cache target is not a regular file"));
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }

        fs::rename(&temp_path, cache_path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn unique_cache_temp_path(parent: &Path) -> PathBuf {
    let unique = CACHE_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    parent.join(format!(
        ".saltbox-facts-cache.{}.{unique}.tmp",
        std::process::id()
    ))
}

async fn fetch_ip_from_url(client: &Client, url: &str, is_ipv6: bool) -> Result<String, String> {
    let ip_label = if is_ipv6 { "IPv6" } else { "IPv4" };
    match timeout(REQUEST_TIMEOUT, async {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Request failed for {url}: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("HTTP {} received from {url}", response.status()));
        }
        if response.content_length().unwrap_or_default() > MAX_IP_RESPONSE_BYTES {
            return Err(format!("Response body from {url} exceeded 64 bytes"));
        }
        let mut body = response.bytes_stream();
        let mut bytes = Vec::with_capacity(MAX_IP_RESPONSE_BYTES as usize);
        while let Some(chunk) = body
            .try_next()
            .await
            .map_err(|e| format!("Failed to read response body from {url}: {e}"))?
        {
            if bytes.len() + chunk.len() > MAX_IP_RESPONSE_BYTES as usize {
                return Err(format!("Response body from {url} exceeded 64 bytes"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let ip = String::from_utf8(bytes)
            .map_err(|e| format!("Response body from {url} was not valid UTF-8: {e}"))?;
        let ip = ip.trim();
        if validate_ip(ip, is_ipv6) {
            Ok(ip.to_string())
        } else {
            Err(format!(
                "Invalid {ip_label} address '{ip}' received from {url}"
            ))
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!(
            "Timeout after {}s for {url}",
            REQUEST_TIMEOUT.as_secs()
        )),
    }
}

pub fn validate_ip(ip: &str, is_ipv6: bool) -> bool {
    if is_ipv6 {
        ip.parse::<Ipv6Addr>().is_ok()
    } else {
        ip.parse::<Ipv4Addr>().is_ok()
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

pub fn parse_groups(file_path: &str) -> io::Result<HashMap<String, GroupData>> {
    parse_groups_reader(BufReader::new(File::open(file_path)?))
}

pub fn parse_groups_reader<R: BufRead>(reader: R) -> io::Result<HashMap<String, GroupData>> {
    let mut data = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split(':');
        let (Some(name), Some(_), Some(gid)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let group_list = parts.next().map_or_else(Vec::new, |members| {
            members
                .split(',')
                .filter(|member| !member.is_empty())
                .map(String::from)
                .collect()
        });
        data.insert(
            name.to_string(),
            GroupData {
                gid: gid.to_string(),
                group_list,
            },
        );
    }

    Ok(data)
}

pub fn parse_users(file_path: &str) -> io::Result<HashMap<String, UserData>> {
    parse_users_reader(BufReader::new(File::open(file_path)?))
}

pub fn parse_users_reader<R: BufRead>(reader: R) -> io::Result<HashMap<String, UserData>> {
    let mut data = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split(':');
        let (Some(name), Some(_), Some(uid), Some(gid), Some(comment), Some(home), Some(shell)) = (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ) else {
            continue;
        };
        data.insert(
            name.to_string(),
            UserData {
                uid: uid.to_string(),
                gid: gid.to_string(),
                comment: comment.to_string(),
                home: home.to_string(),
                shell: shell.to_string(),
            },
        );
    }

    Ok(data)
}

pub fn get_timezone(timezone_path: &str, localtime_path: &str) -> TimezoneData {
    if let Ok(tz) = env::var("TZ") {
        if let Some(tz) = nonempty_trimmed(&tz) {
            return TimezoneData { timezone: tz };
        }
    }

    if let Ok(content) = std::fs::read_to_string(timezone_path) {
        if let Some(tz) = timezone_from_etc_timezone(&content) {
            return TimezoneData { timezone: tz };
        }
    }

    if let Ok(target) = std::fs::read_link(localtime_path) {
        if let Some(tz) = timezone_from_localtime_target(&target) {
            return TimezoneData { timezone: tz };
        }
    }

    TimezoneData {
        timezone: "Etc/UTC".to_string(),
    }
}

fn nonempty_trimmed(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_string())
}

pub fn timezone_from_etc_timezone(content: &str) -> Option<String> {
    nonempty_trimmed(content)
}

pub fn timezone_from_localtime_target(target: &Path) -> Option<String> {
    let target_str = target.to_string_lossy();
    target_str
        .find("zoneinfo/")
        .and_then(|index| target_str.get(index + "zoneinfo/".len()..))
        .map(str::trim)
        .filter(|tz| !tz.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::io::{BufRead, BufReader as StdBufReader, Cursor, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::{symlink, FileTypeExt, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    static TEST_PATH_COUNTER: AtomicUsize = AtomicUsize::new(0);

    struct TestDirectory {
        path: PathBuf,
    }

    impl TestDirectory {
        fn new() -> Self {
            let unique = TEST_PATH_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "saltbox-facts-test-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self { path }
        }

        fn cache_path(&self) -> PathBuf {
            self.path.join("saltbox-facts-cache.json")
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.path).unwrap();
        }
    }

    struct TestHttpServer {
        url: String,
        requests: Arc<AtomicUsize>,
        shutdown: Arc<AtomicBool>,
        thread: Option<JoinHandle<()>>,
    }

    impl TestHttpServer {
        fn start<F>(response: F) -> Self
        where
            F: Fn(usize) -> (&'static str, &'static str, Duration) + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(AtomicUsize::new(0));
            let shutdown = Arc::new(AtomicBool::new(false));
            let thread_requests = Arc::clone(&requests);
            let thread_shutdown = Arc::clone(&shutdown);
            let response = Arc::new(response);
            let server_thread = thread::spawn(move || {
                while !thread_shutdown.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let request_number = thread_requests.fetch_add(1, Ordering::SeqCst) + 1;
                            handle_test_request(stream, response(request_number));
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

        fn request_count(&self) -> usize {
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

    fn handle_test_request(mut stream: TcpStream, (status, body, delay): (&str, &str, Duration)) {
        let mut reader = StdBufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 || line == "\r\n" {
                break;
            }
        }
        thread::sleep(delay);
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    }

    fn server_urls(servers: &[&TestHttpServer]) -> Vec<String> {
        servers.iter().map(|server| server.url.clone()).collect()
    }

    fn url_refs(urls: &[String]) -> Vec<&str> {
        urls.iter().map(String::as_str).collect()
    }

    fn test_lookup_policy(cache_path: &Path, now: u64) -> LookupPolicy<'_> {
        LookupPolicy {
            cache_path,
            now,
            retry_delays: [Duration::ZERO, Duration::ZERO],
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_failed_endpoint_and_one_successful_endpoint_do_not_retry() {
        let failure =
            TestHttpServer::start(|_| ("503 Service Unavailable", "unavailable", Duration::ZERO));
        let success =
            TestHttpServer::start(|_| ("200 OK", "203.0.113.10\n", Duration::from_millis(10)));
        let urls = server_urls(&[&failure, &success]);
        let urls = url_refs(&urls);

        let result = get_ip_with_retry(
            &Client::new(),
            &urls,
            false,
            [Duration::ZERO, Duration::ZERO],
        )
        .await;

        assert_eq!(result, (Some("203.0.113.10".to_string()), None));
        assert_eq!(failure.request_count(), 1);
        assert_eq!(success.request_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn third_round_success_returns_after_two_complete_failed_rounds() {
        let first =
            TestHttpServer::start(|_| ("503 Service Unavailable", "unavailable", Duration::ZERO));
        let second =
            TestHttpServer::start(|_| ("503 Service Unavailable", "unavailable", Duration::ZERO));
        let succeeds_on_third = TestHttpServer::start(|request_number| {
            if request_number == 3 {
                ("200 OK", "203.0.113.20", Duration::from_millis(10))
            } else {
                ("503 Service Unavailable", "unavailable", Duration::ZERO)
            }
        });
        let urls = server_urls(&[&first, &second, &succeeds_on_third]);
        let urls = url_refs(&urls);

        let result = get_ip_with_retry(
            &Client::new(),
            &urls,
            false,
            [Duration::ZERO, Duration::ZERO],
        )
        .await;

        assert_eq!(result, (Some("203.0.113.20".to_string()), None));
        assert_eq!(first.request_count(), 3);
        assert_eq!(second.request_count(), 3);
        assert_eq!(succeeds_on_third.request_count(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn three_failed_rounds_return_attempt_labeled_source_errors() {
        let first =
            TestHttpServer::start(|_| ("503 Service Unavailable", "unavailable", Duration::ZERO));
        let second =
            TestHttpServer::start(|_| ("500 Internal Server Error", "broken", Duration::ZERO));
        let urls = server_urls(&[&first, &second]);
        let urls = url_refs(&urls);

        let (address, error) = get_ip_with_retry(
            &Client::new(),
            &urls,
            false,
            [Duration::ZERO, Duration::ZERO],
        )
        .await;

        assert_eq!(address, None);
        let error = error.unwrap();
        for attempt in 1..=3 {
            assert!(error.contains(&format!("Attempt {attempt}:")));
        }
        assert_eq!(error.matches("HTTP 503").count(), 3);
        assert_eq!(error.matches("HTTP 500").count(), 3);
        assert_eq!(first.request_count(), 3);
        assert_eq!(second.request_count(), 3);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_ipv4_and_ipv6_cache_hits_skip_all_http_requests() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        fs::write(
            &cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "203.0.113.10", "observed_at": 1_780_000_000_u64},
                "ipv6": {"address": "2001:db8::10", "observed_at": 1_780_000_000_u64}
            })
            .to_string(),
        )
        .unwrap();
        let ipv4_server =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let ipv6_server =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let ipv4_urls = server_urls(&[&ipv4_server]);
        let ipv6_urls = server_urls(&[&ipv6_server]);
        let ipv4_urls = url_refs(&ipv4_urls);
        let ipv6_urls = url_refs(&ipv6_urls);

        let (ipv4, ipv6) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_000_899),
        )
        .await;

        assert_eq!(ipv4, (Some("203.0.113.10".to_string()), None));
        assert_eq!(ipv6, (Some("2001:db8::10".to_string()), None));
        assert_eq!(ipv4_server.request_count(), 0);
        assert_eq!(ipv6_server.request_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ipv4_and_ipv6_cache_expiration_refresh_independently() {
        let now = 1_780_001_000;

        let ipv4_directory = TestDirectory::new();
        let ipv4_cache_path = ipv4_directory.cache_path();
        fs::write(
            &ipv4_cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "203.0.113.1", "observed_at": now - 900},
                "ipv6": {"address": "2001:db8::1", "observed_at": now - 899}
            })
            .to_string(),
        )
        .unwrap();
        let ipv4_server =
            TestHttpServer::start(|_| ("200 OK", "203.0.113.2", Duration::from_millis(5)));
        let unexpected_ipv6 =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let ipv4_urls = server_urls(&[&ipv4_server]);
        let ipv6_urls = server_urls(&[&unexpected_ipv6]);
        let ipv4_urls = url_refs(&ipv4_urls);
        let ipv6_urls = url_refs(&ipv6_urls);

        let (ipv4, ipv6) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&ipv4_cache_path, now),
        )
        .await;

        assert_eq!(ipv4, (Some("203.0.113.2".to_string()), None));
        assert_eq!(ipv6, (Some("2001:db8::1".to_string()), None));
        assert_eq!(ipv4_server.request_count(), 1);
        assert_eq!(unexpected_ipv6.request_count(), 0);

        let ipv6_directory = TestDirectory::new();
        let ipv6_cache_path = ipv6_directory.cache_path();
        fs::write(
            &ipv6_cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "203.0.113.3", "observed_at": now - 899},
                "ipv6": {"address": "2001:db8::3", "observed_at": now - 900}
            })
            .to_string(),
        )
        .unwrap();
        let unexpected_ipv4 =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let ipv6_server =
            TestHttpServer::start(|_| ("200 OK", "2001:db8::4", Duration::from_millis(5)));
        let ipv4_urls = server_urls(&[&unexpected_ipv4]);
        let ipv6_urls = server_urls(&[&ipv6_server]);
        let ipv4_urls = url_refs(&ipv4_urls);
        let ipv6_urls = url_refs(&ipv6_urls);

        let (ipv4, ipv6) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&ipv6_cache_path, now),
        )
        .await;

        assert_eq!(ipv4, (Some("203.0.113.3".to_string()), None));
        assert_eq!(ipv6, (Some("2001:db8::4".to_string()), None));
        assert_eq!(unexpected_ipv4.request_count(), 0);
        assert_eq!(ipv6_server.request_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_cache_variants_are_live_lookup_misses() {
        let now = 1_780_001_000;
        let cases = [
            ("malformed JSON", "{not json".to_string()),
            (
                "unsupported schema",
                json!({
                    "version": 2,
                    "ipv4": {"address": "203.0.113.10", "observed_at": now}
                })
                .to_string(),
            ),
            (
                "wrong address family",
                json!({
                    "version": 1,
                    "ipv4": {"address": "2001:db8::10", "observed_at": now}
                })
                .to_string(),
            ),
            (
                "expired timestamp",
                json!({
                    "version": 1,
                    "ipv4": {"address": "203.0.113.10", "observed_at": now - 900}
                })
                .to_string(),
            ),
            (
                "future timestamp",
                json!({
                    "version": 1,
                    "ipv4": {"address": "203.0.113.10", "observed_at": now + 1}
                })
                .to_string(),
            ),
        ];

        for (case, cache) in cases {
            let directory = TestDirectory::new();
            let cache_path = directory.cache_path();
            fs::write(&cache_path, cache).unwrap();
            let server =
                TestHttpServer::start(|_| ("200 OK", "203.0.113.99", Duration::from_millis(5)));
            let ipv4_urls = server_urls(&[&server]);
            let ipv4_urls = url_refs(&ipv4_urls);

            let (ipv4, _) = resolve_public_ips_with_policy(
                &Client::new(),
                &ipv4_urls,
                &[],
                false,
                "IPv6 unavailable".to_string(),
                test_lookup_policy(&cache_path, now),
            )
            .await;

            assert_eq!(
                ipv4,
                (Some("203.0.113.99".to_string()), None),
                "{case} should miss"
            );
            assert_eq!(server.request_count(), 1, "{case} should use HTTP");
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_size_limit_is_exactly_4096_bytes() {
        let now = 1_780_001_000;
        let cache_json = json!({
            "version": 1,
            "ipv4": {"address": "203.0.113.70", "observed_at": now}
        })
        .to_string();

        let boundary_directory = TestDirectory::new();
        let boundary_cache_path = boundary_directory.cache_path();
        let mut boundary_cache = cache_json.as_bytes().to_vec();
        boundary_cache.resize(4096, b' ');
        fs::write(&boundary_cache_path, &boundary_cache).unwrap();
        let unexpected_server =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let boundary_urls = server_urls(&[&unexpected_server]);
        let boundary_urls = url_refs(&boundary_urls);

        let (boundary_ipv4, _) = resolve_public_ips_with_policy(
            &Client::new(),
            &boundary_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&boundary_cache_path, now),
        )
        .await;

        assert_eq!(boundary_ipv4, (Some("203.0.113.70".to_string()), None));
        assert_eq!(unexpected_server.request_count(), 0);

        let oversized_directory = TestDirectory::new();
        let oversized_cache_path = oversized_directory.cache_path();
        let mut oversized_cache = cache_json.into_bytes();
        oversized_cache.resize(4097, b' ');
        fs::write(&oversized_cache_path, &oversized_cache).unwrap();
        let live_server =
            TestHttpServer::start(|_| ("200 OK", "203.0.113.71", Duration::from_millis(5)));
        let oversized_urls = server_urls(&[&live_server]);
        let oversized_urls = url_refs(&oversized_urls);

        let (oversized_ipv4, _) = resolve_public_ips_with_policy(
            &Client::new(),
            &oversized_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&oversized_cache_path, now),
        )
        .await;

        assert_eq!(oversized_ipv4, (Some("203.0.113.71".to_string()), None));
        assert_eq!(live_server.request_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_cache_and_failed_live_lookup_leave_cache_bytes_unchanged() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let original = b"{\n  \"version\": 1,\n  \"ipv4\": {\"address\": \"203.0.113.10\", \"observed_at\": 1779999000}\n}\n";
        fs::write(&cache_path, original).unwrap();
        let server =
            TestHttpServer::start(|_| ("503 Service Unavailable", "unavailable", Duration::ZERO));
        let ipv4_urls = server_urls(&[&server]);
        let ipv4_urls = url_refs(&ipv4_urls);

        let (ipv4, _) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_000),
        )
        .await;

        assert!(ipv4.0.is_none());
        assert_eq!(server.request_count(), 3);
        assert_eq!(fs::read(&cache_path).unwrap(), original);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn mixed_live_results_update_only_the_successful_family() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let now = 1_780_001_000;
        let original_cache = json!({
            "version": 1,
            "ipv4": {"address": "203.0.113.10", "observed_at": 1_780_000_000_u64},
            "ipv6": {"address": "2001:db8::10", "observed_at": 1_780_000_000_u64}
        });
        fs::write(&cache_path, original_cache.to_string()).unwrap();
        let ipv4_server =
            TestHttpServer::start(|_| ("200 OK", "203.0.113.11", Duration::from_millis(5)));
        let ipv6_server =
            TestHttpServer::start(|_| ("503 Service Unavailable", "unavailable", Duration::ZERO));
        let ipv4_urls = server_urls(&[&ipv4_server]);
        let ipv6_urls = server_urls(&[&ipv6_server]);
        let ipv4_urls = url_refs(&ipv4_urls);
        let ipv6_urls = url_refs(&ipv6_urls);

        let (ipv4, ipv6) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, now),
        )
        .await;

        assert_eq!(ipv4, (Some("203.0.113.11".to_string()), None));
        assert!(ipv6.0.is_none());
        assert!(ipv6.1.unwrap().contains("Attempt 3:"));
        assert_eq!(ipv4_server.request_count(), 1);
        assert_eq!(ipv6_server.request_count(), 3);

        let updated_cache: serde_json::Value =
            serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(
            updated_cache["ipv4"],
            json!({"address": "203.0.113.11", "observed_at": now})
        );
        assert_eq!(updated_cache["ipv6"], original_cache["ipv6"]);
        assert_eq!(updated_cache["ipv6"]["observed_at"], 1_780_000_000_u64);
    }

    #[test]
    fn concurrent_complementary_writers_merge_the_latest_cache() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let lock_path = directory.path.join(".saltbox-facts-cache.lock");
        let now = 1_780_001_000;
        let old_cache = json!({
            "version": 1,
            "ipv4": {"address": "203.0.113.10", "observed_at": 1_780_000_000_u64},
            "ipv6": {"address": "2001:db8::10", "observed_at": 1_780_000_000_u64}
        });
        fs::write(&cache_path, old_cache.to_string()).unwrap();
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&lock_path)
            .unwrap();
        lock_file.try_lock().unwrap();

        let start = Arc::new(Barrier::new(3));
        let ipv4_cache_path = cache_path.clone();
        let ipv4_start = Arc::clone(&start);
        let ipv4_writer = thread::spawn(move || {
            let snapshot = load_cache(&ipv4_cache_path).unwrap();
            assert_eq!(snapshot.ipv4.unwrap().address, "203.0.113.10");
            ipv4_start.wait();
            merge_successful_cache_entries(
                &ipv4_cache_path,
                Some("203.0.113.11".to_string()),
                None,
                now,
            )
        });

        let ipv6_cache_path = cache_path.clone();
        let ipv6_start = Arc::clone(&start);
        let ipv6_writer = thread::spawn(move || {
            let snapshot = load_cache(&ipv6_cache_path).unwrap();
            assert_eq!(snapshot.ipv6.unwrap().address, "2001:db8::10");
            ipv6_start.wait();
            merge_successful_cache_entries(
                &ipv6_cache_path,
                None,
                Some("2001:db8::11".to_string()),
                now,
            )
        });

        start.wait();
        thread::sleep(Duration::from_millis(50));
        let while_locked: serde_json::Value =
            serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(while_locked, old_cache);
        lock_file.unlock().unwrap();
        drop(lock_file);

        ipv4_writer.join().unwrap().unwrap();
        ipv6_writer.join().unwrap().unwrap();

        let merged: serde_json::Value =
            serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(
            merged["ipv4"],
            json!({"address": "203.0.113.11", "observed_at": now})
        );
        assert_eq!(
            merged["ipv6"],
            json!({"address": "2001:db8::11", "observed_at": now})
        );
        assert!(fs::metadata(&lock_path).unwrap().file_type().is_file());
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn held_cache_lock_times_out_without_changing_live_result() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let lock_path = directory.path.join(".saltbox-facts-cache.lock");
        let original_cache = json!({
            "version": 1,
            "ipv4": {"address": "203.0.113.20", "observed_at": 1_780_000_000_u64}
        })
        .to_string();
        fs::write(&cache_path, &original_cache).unwrap();
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&lock_path)
            .unwrap();
        lock_file.try_lock().unwrap();
        let server =
            TestHttpServer::start(|_| ("200 OK", "203.0.113.21", Duration::from_millis(5)));
        let server_url = server.url.clone();
        let thread_cache_path = cache_path.clone();
        let (sender, receiver) = mpsc::sync_channel(1);

        let resolver_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let started = Instant::now();
            let result = runtime.block_on(async {
                let urls = [server_url.as_str()];
                resolve_public_ips_with_policy(
                    &Client::new(),
                    &urls,
                    &[],
                    false,
                    "IPv6 unavailable".to_string(),
                    test_lookup_policy(&thread_cache_path, 1_780_001_000),
                )
                .await
            });
            sender.send((result, started.elapsed())).unwrap();
        });

        let received = receiver.recv_timeout(Duration::from_secs(2));
        lock_file.unlock().unwrap();
        drop(lock_file);
        resolver_thread.join().unwrap();

        let ((ipv4, _), elapsed) = received.expect("lock acquisition must time out");
        assert_eq!(ipv4, (Some("203.0.113.21".to_string()), None));
        assert!(elapsed >= Duration::from_secs(1), "elapsed: {elapsed:?}");
        assert!(
            elapsed < Duration::from_millis(1500),
            "elapsed: {elapsed:?}"
        );
        assert_eq!(fs::read_to_string(&cache_path).unwrap(), original_cache);
        assert_eq!(server.request_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nonregular_lock_targets_are_soft_write_failures() {
        for target_kind in ["directory", "fifo", "symlink"] {
            let directory = TestDirectory::new();
            let cache_path = directory.cache_path();
            let lock_path = directory.path.join(".saltbox-facts-cache.lock");
            match target_kind {
                "directory" => fs::create_dir(&lock_path).unwrap(),
                "fifo" => assert!(Command::new("mkfifo")
                    .arg(&lock_path)
                    .status()
                    .unwrap()
                    .success()),
                "symlink" => {
                    let target = directory.path.join("lock-target");
                    fs::write(&target, "do not touch").unwrap();
                    symlink(&target, &lock_path).unwrap();
                }
                _ => unreachable!(),
            }
            let server =
                TestHttpServer::start(|_| ("200 OK", "203.0.113.30", Duration::from_millis(5)));
            let urls = server_urls(&[&server]);
            let urls = url_refs(&urls);

            let (ipv4, _) = resolve_public_ips_with_policy(
                &Client::new(),
                &urls,
                &[],
                false,
                "IPv6 unavailable".to_string(),
                test_lookup_policy(&cache_path, 1_780_001_000),
            )
            .await;

            assert_eq!(
                ipv4,
                (Some("203.0.113.30".to_string()), None),
                "{target_kind} lock target must not hide live success"
            );
            assert_eq!(server.request_count(), 1);
            assert!(!cache_path.exists());
            let file_type = fs::symlink_metadata(&lock_path).unwrap().file_type();
            assert!(
                match target_kind {
                    "directory" => file_type.is_dir(),
                    "fifo" => file_type.is_fifo(),
                    "symlink" => file_type.is_symlink(),
                    _ => false,
                },
                "{target_kind} lock target changed type"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn refreshing_one_family_atomically_preserves_the_other_and_sets_mode() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let now = 1_780_001_000;
        fs::write(
            &cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "203.0.113.10", "observed_at": now - 900},
                "ipv6": {"address": "2001:db8::10", "observed_at": now - 899}
            })
            .to_string(),
        )
        .unwrap();
        let server =
            TestHttpServer::start(|_| ("200 OK", "203.0.113.11", Duration::from_millis(5)));
        let ipv4_urls = server_urls(&[&server]);
        let ipv4_urls = url_refs(&ipv4_urls);

        let (ipv4, ipv6) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, now),
        )
        .await;

        assert_eq!(ipv4, (Some("203.0.113.11".to_string()), None));
        assert_eq!(ipv6, (Some("2001:db8::10".to_string()), None));
        let cache: serde_json::Value =
            serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(cache["ipv4"]["address"], "203.0.113.11");
        assert_eq!(cache["ipv4"]["observed_at"], now);
        assert_eq!(cache["ipv6"]["address"], "2001:db8::10");
        assert_eq!(cache["ipv6"]["observed_at"], now - 899);
        assert_eq!(
            fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777,
            0o644
        );
        let mut persisted_files = fs::read_dir(&directory.path)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        persisted_files.sort();
        assert_eq!(
            persisted_files,
            [".saltbox-facts-cache.lock", "saltbox-facts-cache.json"]
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_read_and_write_failure_cannot_hide_live_success() {
        let directory = TestDirectory::new();
        let non_regular_cache_path = directory.path.join("cache-target");
        fs::create_dir(&non_regular_cache_path).unwrap();
        let server =
            TestHttpServer::start(|_| ("200 OK", "203.0.113.50", Duration::from_millis(5)));
        let ipv4_urls = server_urls(&[&server]);
        let ipv4_urls = url_refs(&ipv4_urls);

        let (ipv4, _) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&non_regular_cache_path, 1_780_001_000),
        )
        .await;

        assert_eq!(ipv4, (Some("203.0.113.50".to_string()), None));
        assert!(non_regular_cache_path.is_dir());
    }

    #[test]
    fn fifo_cache_target_is_a_bounded_soft_miss() {
        let directory = TestDirectory::new();
        let fifo_path = directory.path.join("cache-fifo");
        assert!(Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .unwrap()
            .success());
        assert!(fs::symlink_metadata(&fifo_path)
            .unwrap()
            .file_type()
            .is_fifo());
        let server =
            TestHttpServer::start(|_| ("200 OK", "203.0.113.60", Duration::from_millis(5)));
        let server_url = server.url.clone();
        let thread_fifo_path = fifo_path.clone();
        let (sender, receiver) = mpsc::sync_channel(1);

        thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let result = runtime.block_on(async {
                let urls = [server_url.as_str()];
                resolve_public_ips_with_policy(
                    &Client::new(),
                    &urls,
                    &[],
                    false,
                    "IPv6 unavailable".to_string(),
                    test_lookup_policy(&thread_fifo_path, 1_780_001_000),
                )
                .await
            });
            sender.send(result).unwrap();
        });

        let (ipv4, _) = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("FIFO cache resolution must not block");
        assert_eq!(ipv4, (Some("203.0.113.60".to_string()), None));
        assert_eq!(server.request_count(), 1);
        assert!(fs::symlink_metadata(&fifo_path)
            .unwrap()
            .file_type()
            .is_fifo());
    }

    #[test]
    fn output_schema_matches_saltbox_contract() {
        let output = Output {
            saltbox_facts_version: "1.2.3",
            ip: IpOutput {
                public_ip: String::new(),
                public_ipv6: String::new(),
                error_ipv4: Some("IPv4 error".to_string()),
                error_ipv6: Some("IPv6 error".to_string()),
                failed_ipv4: true,
                failed_ipv6: true,
                ipv6_check_error: None,
            },
            groups: HashMap::new(),
            users: HashMap::new(),
            timezone: TimezoneData {
                timezone: "Etc/UTC".to_string(),
            },
        };

        let value = serde_json::to_value(output).unwrap();
        assert_eq!(
            value["ip"].as_object().unwrap().keys().collect::<Vec<_>>(),
            [
                "error_ipv4",
                "error_ipv6",
                "failed_ipv4",
                "failed_ipv6",
                "ipv6_check_error",
                "public_ip",
                "public_ipv6",
            ]
        );
        assert!(value["groups"].is_object());
        assert!(value["users"].is_object());
        assert!(value["timezone"]["timezone"].is_string());
        assert!(value["saltbox_facts_version"].is_string());
    }

    #[test]
    fn sorts_json_keys_alphabetically_recursively() {
        let value = serde_json::json!({
            "z": 1,
            "a": {"d": 2, "b": 3},
            "m": [{"k": 1, "c": 2}]
        });

        assert_eq!(
            serde_json::to_string(&sort_json_value(value)).unwrap(),
            r#"{"a":{"b":3,"d":2},"m":[{"c":2,"k":1}],"z":1}"#
        );
    }

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
    fn parses_empty_group_members_as_an_empty_list() {
        let groups = parse_groups_reader(Cursor::new("root:x:0:\n")).unwrap();
        assert!(groups["root"].group_list.is_empty());
    }

    #[test]
    fn parses_group_members() {
        let groups = parse_groups_reader(Cursor::new("docker:x:1001:salty,other\n")).unwrap();
        assert_eq!(groups["docker"].gid, "1001");
        assert_eq!(groups["docker"].group_list, ["salty", "other"]);
    }

    #[test]
    fn parses_user_fields_required_by_saltbox() {
        let users =
            parse_users_reader(Cursor::new("salty:x:1000:1000::/home/salty:/bin/zsh\n")).unwrap();
        assert_eq!(users["salty"].uid, "1000");
        assert_eq!(users["salty"].gid, "1000");
    }

    #[test]
    fn trims_timezone_from_etc_timezone_file() {
        assert_eq!(
            timezone_from_etc_timezone("Europe/Copenhagen\n"),
            Some("Europe/Copenhagen".to_string())
        );
    }

    #[test]
    fn returns_none_for_empty_etc_timezone_content() {
        assert_eq!(timezone_from_etc_timezone("   \n\t"), None);
    }

    #[test]
    fn extracts_timezone_from_zoneinfo_localtime_target() {
        let target = Path::new("/usr/share/zoneinfo/Europe/Copenhagen");
        assert_eq!(
            timezone_from_localtime_target(target),
            Some("Europe/Copenhagen".to_string())
        );
    }

    #[test]
    fn returns_none_for_non_zoneinfo_localtime_target() {
        assert_eq!(
            timezone_from_localtime_target(Path::new("/var/lib/custom/localtime")),
            None
        );
    }

    #[test]
    fn validates_ip_address_families() {
        assert!(validate_ip("192.0.2.1", false));
        assert!(!validate_ip("2001:db8::1", false));
        assert!(validate_ip("2001:db8::1", true));
        assert!(!validate_ip("192.0.2.1", true));
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
