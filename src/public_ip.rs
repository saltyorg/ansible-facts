use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::TryStreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::time::timeout;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
pub const PUBLIC_IP_CACHE_PATH: &str = "/var/cache/saltbox/facts/public-ip.json";
const MAX_IP_RESPONSE_BYTES: u64 = 64;
const CACHE_VERSION: u8 = 1;
const CACHE_TTL_SECONDS: u64 = 900;
const MAX_CACHE_BYTES: usize = 4096;
const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
const CACHE_LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
const CACHE_NAMESPACE_MODE: u32 = 0o755;
const CACHE_DIRECTORY_MODE: u32 = 0o700;
const CACHE_FILE_MODE: u32 = 0o600;
const CACHE_LOCK_FILE_NAME: &str = ".public-ip.lock";
const RETRY_DELAYS: [Duration; 2] = [Duration::from_millis(250), Duration::from_millis(750)];
const O_DIRECTORY: i32 = 0o200000;
const O_NONBLOCK: i32 = 0o4000;
const O_NOFOLLOW: i32 = 0o400000;
static CACHE_TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

type IpLookupResult = (Option<String>, Option<String>);

#[derive(Clone, Copy)]
struct LookupPolicy<'a> {
    cache_path: &'a Path,
    now: u64,
    retry_delays: [Duration; 2],
    request_timeout: Duration,
    cache_lock_timeout: Duration,
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

pub async fn get_ip(
    client: &Client,
    urls: &[&str],
    is_ipv6: bool,
) -> (Option<String>, Option<String>) {
    get_ip_with_timeout(client, urls, is_ipv6, REQUEST_TIMEOUT).await
}

async fn get_ip_with_timeout(
    client: &Client,
    urls: &[&str],
    is_ipv6: bool,
    request_timeout: Duration,
) -> (Option<String>, Option<String>) {
    if urls.is_empty() {
        return (
            None,
            Some("All requests failed with unknown errors".to_string()),
        );
    }

    let mut errors = vec![None; urls.len()];
    let mut requests = FuturesUnordered::new();

    for (index, &url) in urls.iter().enumerate() {
        requests.push(async move {
            (
                index,
                fetch_ip_from_url(client, url, is_ipv6, request_timeout).await,
            )
        });
    }

    while let Some((index, result)) = requests.next().await {
        match result {
            Ok(ip) => return (Some(ip), None),
            Err(error) => errors[index] = Some(error),
        }
    }

    let combined_error = if errors.iter().all(Option::is_none) {
        "All requests failed with unknown errors".to_string()
    } else {
        errors.into_iter().flatten().collect::<Vec<_>>().join("; ")
    };

    (None, Some(combined_error))
}

async fn get_ip_with_retry_with_timeout(
    client: &Client,
    urls: &[&str],
    is_ipv6: bool,
    retry_delays: [Duration; 2],
    request_timeout: Duration,
) -> (Option<String>, Option<String>) {
    let mut attempt_errors = Vec::with_capacity(3);

    for attempt in 0..3 {
        let (address, error) = get_ip_with_timeout(client, urls, is_ipv6, request_timeout).await;
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
            request_timeout: REQUEST_TIMEOUT,
            cache_lock_timeout: CACHE_LOCK_TIMEOUT,
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
    let cache_path = policy.cache_path.to_path_buf();
    let loaded_cache = tokio::task::spawn_blocking(move || load_cache(&cache_path))
        .await
        .ok()
        .flatten();
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
                let result = get_ip_with_retry_with_timeout(
                    client,
                    ipv4_urls,
                    false,
                    policy.retry_delays,
                    policy.request_timeout,
                )
                .await;
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
                let result = get_ip_with_retry_with_timeout(
                    client,
                    ipv6_urls,
                    true,
                    policy.retry_delays,
                    policy.request_timeout,
                )
                .await;
                let live_address = result.0.clone();
                (result, live_address)
            }
        }
    };

    let ((ipv4_result, live_ipv4), (ipv6_result, live_ipv6)) =
        tokio::join!(ipv4_future, ipv6_future);

    if live_ipv4.is_some() || live_ipv6.is_some() {
        let cache_path = policy.cache_path.to_path_buf();
        let _ = tokio::task::spawn_blocking(move || {
            merge_successful_cache_entries_with_timeout(
                &cache_path,
                live_ipv4,
                live_ipv6,
                policy.now,
                policy.cache_lock_timeout,
            )
        })
        .await;
    }

    (ipv4_result, ipv6_result)
}

fn load_cache(cache_path: &Path) -> Option<PublicIpCache> {
    validate_cache_parent(cache_path).ok()?;
    let cache_file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(cache_path)
        .ok()?;
    let metadata = cache_file.metadata().ok()?;
    if !metadata.file_type().is_file()
        || validate_owner(&metadata, effective_uid()).is_err()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.len() > MAX_CACHE_BYTES as u64
    {
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
    (age < CACHE_TTL_SECONDS)
        .then(|| canonical_public_ip(&entry.address, is_ipv6))
        .flatten()
}

fn cache_for_update(cache: Option<PublicIpCache>) -> PublicIpCache {
    let Some(mut cache) = cache.filter(|cache| cache.version == CACHE_VERSION) else {
        return PublicIpCache::default();
    };
    cache.ipv4 = cache
        .ipv4
        .and_then(|entry| canonical_cache_entry(entry, false));
    cache.ipv6 = cache
        .ipv6
        .and_then(|entry| canonical_cache_entry(entry, true));
    cache
}

fn canonical_cache_entry(mut entry: CacheEntry, is_ipv6: bool) -> Option<CacheEntry> {
    entry.address = canonical_public_ip(&entry.address, is_ipv6)?;
    Some(entry)
}

fn merge_successful_cache_entries_with_timeout(
    cache_path: &Path,
    live_ipv4: Option<String>,
    live_ipv6: Option<String>,
    now: u64,
    cache_lock_timeout: Duration,
) -> io::Result<()> {
    let parent = cache_path
        .parent()
        .ok_or_else(|| io::Error::other("cache path has no parent directory"))?;
    ensure_cache_parent(cache_path)?;
    let lock_path = parent.join(CACHE_LOCK_FILE_NAME);
    let lock_file = acquire_cache_lock(&lock_path, cache_lock_timeout)?;

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

fn ensure_cache_parent(cache_path: &Path) -> io::Result<()> {
    let (namespace, parent) = cache_directories(cache_path)?;
    ensure_directory(namespace, CACHE_NAMESPACE_MODE, false)?;
    ensure_directory(parent, CACHE_DIRECTORY_MODE, true)
}

fn validate_cache_parent(cache_path: &Path) -> io::Result<()> {
    let (namespace, parent) = cache_directories(cache_path)?;
    validate_directory_mode(&open_directory(namespace)?, false)?;
    validate_directory_mode(&open_directory(parent)?, true)?;
    Ok(())
}

fn cache_directories(cache_path: &Path) -> io::Result<(&Path, &Path)> {
    let parent = cache_path
        .parent()
        .ok_or_else(|| io::Error::other("cache path has no parent directory"))?;
    let namespace = parent
        .parent()
        .ok_or_else(|| io::Error::other("cache directory has no parent directory"))?;
    Ok((namespace, parent))
}

fn ensure_directory(path: &Path, mode: u32, reconcile_mode: bool) -> io::Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.mode(mode);
    let created = match builder.create(path) {
        Ok(()) => true,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error),
    };

    let directory = open_directory(path)?;
    validate_owner(&directory.metadata()?, effective_uid())?;
    if created || reconcile_mode {
        directory.set_permissions(fs::Permissions::from_mode(mode))?;
    }
    validate_directory_mode(&directory, reconcile_mode)?;
    Ok(())
}

fn validate_directory_mode(directory: &File, private: bool) -> io::Result<()> {
    let metadata = directory.metadata()?;
    validate_owner(&metadata, effective_uid())?;
    let forbidden_mode = if private { 0o077 } else { 0o022 };
    if metadata.permissions().mode() & forbidden_mode != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cache directory permissions are not trusted",
        ));
    }
    Ok(())
}

fn validate_owner(metadata: &fs::Metadata, expected_uid: u32) -> io::Result<()> {
    if metadata.uid() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cache artifact is not owned by the effective user",
        ));
    }
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: geteuid has no preconditions and does not dereference pointers.
    unsafe { libc::geteuid() }
}

fn open_directory(path: &Path) -> io::Result<File> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(O_DIRECTORY | O_NOFOLLOW)
        .open(path)?;
    if !directory.metadata()?.file_type().is_dir() {
        return Err(io::Error::other(
            "cache directory target is not a directory",
        ));
    }
    Ok(directory)
}

fn acquire_cache_lock(lock_path: &Path, lock_timeout: Duration) -> io::Result<File> {
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(CACHE_FILE_MODE)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(lock_path)?;
    let metadata = lock_file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::other("cache lock target is not a regular file"));
    }
    validate_owner(&metadata, effective_uid())?;
    lock_file.set_permissions(fs::Permissions::from_mode(CACHE_FILE_MODE))?;
    let started = Instant::now();
    loop {
        match lock_file.try_lock() {
            Ok(()) => return Ok(lock_file),
            Err(TryLockError::WouldBlock) => {
                let elapsed = started.elapsed();
                if elapsed >= lock_timeout {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "timed out acquiring cache lock",
                    ));
                }
                std::thread::sleep(CACHE_LOCK_RETRY_DELAY.min(lock_timeout - elapsed));
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
        validate_owner(&metadata, effective_uid())?;
    }

    let parent = cache_path
        .parent()
        .ok_or_else(|| io::Error::other("cache path has no parent directory"))?;
    let temp_path = unique_cache_temp_path(parent);
    let result = (|| {
        let mut temp = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(CACHE_FILE_MODE)
            .open(&temp_path)?;
        serde_json::to_writer(&mut temp, cache).map_err(io::Error::other)?;
        temp.write_all(b"\n")?;
        temp.set_permissions(fs::Permissions::from_mode(CACHE_FILE_MODE))?;
        temp.sync_all()?;

        match fs::symlink_metadata(cache_path) {
            Ok(metadata) if !metadata.file_type().is_file() => {
                return Err(io::Error::other("cache target is not a regular file"));
            }
            Ok(metadata) => validate_owner(&metadata, effective_uid())?,
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
    parent.join(format!(".public-ip.{}.{unique}.tmp", std::process::id()))
}

async fn fetch_ip_from_url(
    client: &Client,
    url: &str,
    is_ipv6: bool,
    request_timeout: Duration,
) -> Result<String, String> {
    let ip_label = if is_ipv6 { "IPv6" } else { "IPv4" };
    match timeout(request_timeout, async {
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
        if let Some(ip) = canonical_public_ip(ip, is_ipv6) {
            Ok(ip)
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
            "Timeout after {} for {url}",
            format_timeout(request_timeout)
        )),
    }
}

fn format_timeout(timeout: Duration) -> String {
    if timeout.subsec_nanos() == 0 {
        format!("{}s", timeout.as_secs())
    } else {
        format!("{}ms", timeout.as_millis())
    }
}

pub fn validate_ip(ip: &str, is_ipv6: bool) -> bool {
    canonical_public_ip(ip, is_ipv6).is_some()
}

fn canonical_public_ip(ip: &str, is_ipv6: bool) -> Option<String> {
    // Echo services report what a request looks like at their boundary; they
    // are availability sources, not a consensus system. Trust syntax and the
    // requested family instead of trying to maintain a LAN/IANA denylist.
    let ip = ip.trim();
    if is_ipv6 {
        ip.parse::<Ipv6Addr>()
            .ok()
            .map(|address| address.to_string())
    } else {
        ip.parse::<Ipv4Addr>()
            .ok()
            .map(|address| address.to_string())
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
mod tests {
    use super::*;
    use serde_json::json;
    use std::fs;
    use std::io::{BufRead, BufReader as StdBufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, PermissionsExt};
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc, Barrier, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    struct TestDirectory {
        directory: TempDir,
    }

    impl TestDirectory {
        fn new() -> Self {
            let directory = tempfile::Builder::new()
                .prefix("saltbox-facts-test-")
                .tempdir()
                .unwrap();
            fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
            Self { directory }
        }

        fn path(&self) -> &Path {
            self.directory.path()
        }

        fn cache_path(&self) -> PathBuf {
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

    fn write_private_cache(path: &Path, contents: impl AsRef<[u8]>) {
        fs::write(path, contents).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
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
            Self::start_with_handler(move |stream, request_number| {
                handle_test_request(stream, response(request_number));
            })
        }

        fn start_with_handler<F>(handler: F) -> Self
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
        if let Err(error) = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        ) {
            assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        }
    }

    fn handle_raw_test_request(
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
            request_timeout: Duration::from_millis(25),
            cache_lock_timeout: Duration::from_millis(25),
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn declared_response_size_over_64_bytes_is_rejected_before_reading_body() {
        // Catches removal of the Content-Length boundary check.
        let server = TestHttpServer::start_with_handler(|stream, _| {
            handle_raw_test_request(
                stream,
                "200 OK",
                &[("Content-Length", "65")],
                &[b"8.8.8.8"],
                Duration::ZERO,
            );
        });
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let (address, error) = get_ip(&Client::new(), &urls, false).await;

        assert_eq!(address, None);
        assert!(error.unwrap().contains("exceeded 64 bytes"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn chunked_response_over_64_bytes_is_rejected_after_streaming_body() {
        // Catches removal of aggregate byte enforcement for unknown-length streams.
        let first_chunk = [b' '; 64];
        let server = TestHttpServer::start_with_handler(move |stream, _| {
            handle_raw_test_request(
                stream,
                "200 OK",
                &[("Transfer-Encoding", "chunked")],
                &[&first_chunk, b"x"],
                Duration::ZERO,
            );
        });
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let (address, error) = get_ip(&Client::new(), &urls, false).await;

        assert_eq!(address, None);
        assert!(error.unwrap().contains("exceeded 64 bytes"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_utf8_response_body_is_rejected() {
        // Catches lossy response decoding that could turn invalid bytes into accepted text.
        let server = TestHttpServer::start_with_handler(|stream, _| {
            handle_raw_test_request(
                stream,
                "200 OK",
                &[("Content-Length", "7")],
                &[b"8.8.8.\xff"],
                Duration::ZERO,
            );
        });
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let (address, error) = get_ip(&Client::new(), &urls, false).await;

        assert_eq!(address, None);
        assert!(error.unwrap().contains("not valid UTF-8"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_success_status_is_rejected_without_accepting_its_body() {
        // Catches accepting a syntactically valid body without enforcing HTTP success.
        let server =
            TestHttpServer::start(|_| ("503 Service Unavailable", "8.8.8.8", Duration::ZERO));
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let (address, error) = get_ip(&Client::new(), &urls, false).await;

        assert_eq!(address, None);
        assert!(error.unwrap().contains("HTTP 503"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn response_with_wrong_address_family_is_rejected() {
        // Catches accepting any parseable address instead of the requested family.
        let server = TestHttpServer::start(|_| ("200 OK", "2606:4700:4700::1111", Duration::ZERO));
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let (address, error) = get_ip(&Client::new(), &urls, false).await;

        assert_eq!(address, None);
        assert!(error.unwrap().contains("Invalid IPv4 address"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_timeout_uses_the_private_millisecond_policy() {
        // Catches hard-coding the three-second production timeout in resolver calls.
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.8.8", Duration::from_millis(100)));
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

        assert_eq!(ipv4.0, None);
        assert!(ipv4.1.unwrap().contains("Timeout after 25ms"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_failed_endpoint_and_one_successful_endpoint_do_not_retry() {
        let failure =
            TestHttpServer::start(|_| ("503 Service Unavailable", "unavailable", Duration::ZERO));
        let success =
            TestHttpServer::start(|_| ("200 OK", "8.8.4.10\n", Duration::from_millis(10)));
        let urls = server_urls(&[&failure, &success]);
        let urls = url_refs(&urls);

        let result = get_ip_with_retry_with_timeout(
            &Client::new(),
            &urls,
            false,
            [Duration::ZERO, Duration::ZERO],
            REQUEST_TIMEOUT,
        )
        .await;

        assert_eq!(result, (Some("8.8.4.10".to_string()), None));
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
                ("200 OK", "8.8.4.20", Duration::from_millis(10))
            } else {
                ("503 Service Unavailable", "unavailable", Duration::ZERO)
            }
        });
        let urls = server_urls(&[&first, &second, &succeeds_on_third]);
        let urls = url_refs(&urls);

        let result = get_ip_with_retry_with_timeout(
            &Client::new(),
            &urls,
            false,
            [Duration::ZERO, Duration::ZERO],
            REQUEST_TIMEOUT,
        )
        .await;

        assert_eq!(result, (Some("8.8.4.20".to_string()), None));
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

        let (address, error) = get_ip_with_retry_with_timeout(
            &Client::new(),
            &urls,
            false,
            [Duration::ZERO, Duration::ZERO],
            REQUEST_TIMEOUT,
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
    async fn failure_diagnostics_follow_configured_source_order() {
        let configured_first =
            TestHttpServer::start(|_| ("503 Service Unavailable", "first", Duration::ZERO));
        let configured_second =
            TestHttpServer::start(|_| ("500 Internal Server Error", "second", Duration::ZERO));
        let urls = server_urls(&[&configured_first, &configured_second]);
        let urls = url_refs(&urls);

        let (_, error) = get_ip(&Client::new(), &urls, false).await;

        let error = error.unwrap();
        assert!(
            error.find(&configured_first.url).unwrap()
                < error.find(&configured_second.url).unwrap(),
            "diagnostics did not preserve configured order: {error}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn first_valid_source_wins_even_when_configured_later() {
        let (first_received_sender, first_received) = mpsc::sync_channel(1);
        let (release_first, release_first_receiver) = mpsc::sync_channel(1);
        let release_first_receiver = Arc::new(Mutex::new(release_first_receiver));
        let configured_first = TestHttpServer::start_with_handler(move |stream, _| {
            first_received_sender.send(()).unwrap();
            release_first_receiver.lock().unwrap().recv().unwrap();
            handle_test_request(stream, ("200 OK", "1.1.1.1", Duration::ZERO));
        });
        let faster_second = TestHttpServer::start(|_| ("200 OK", "8.8.8.8", Duration::ZERO));
        let urls = server_urls(&[&configured_first, &faster_second]);
        let lookup = tokio::spawn(async move {
            let urls = url_refs(&urls);
            get_ip(&Client::new(), &urls, false).await
        });

        tokio::task::spawn_blocking(move || {
            first_received
                .recv_timeout(Duration::from_secs(1))
                .expect("configured first source did not receive its request")
        })
        .await
        .unwrap();
        let result = lookup.await.unwrap();
        release_first.send(()).unwrap();

        assert_eq!(result, (Some("8.8.8.8".to_string()), None));
        assert_eq!(configured_first.request_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_addresses_are_returned_in_canonical_form() {
        let server = TestHttpServer::start(|_| {
            (
                "200 OK",
                "2606:4700:4700:0000:0000:0000:0000:1111",
                Duration::ZERO,
            )
        });
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let result = get_ip(&Client::new(), &urls, true).await;

        assert_eq!(result, (Some("2606:4700:4700::1111".to_string()), None));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_ipv4_and_ipv6_cache_hits_skip_all_http_requests() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        write_private_cache(
            &cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "8.8.4.10", "observed_at": 1_780_000_000_u64},
                "ipv6": {"address": "2606:4700:4700::10", "observed_at": 1_780_000_000_u64}
            })
            .to_string(),
        );
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

        assert_eq!(ipv4, (Some("8.8.4.10".to_string()), None));
        assert_eq!(ipv6, (Some("2606:4700:4700::10".to_string()), None));
        assert_eq!(ipv4_server.request_count(), 0);
        assert_eq!(ipv6_server.request_count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn permissive_cache_artifacts_are_ignored() {
        for (case, directory_mode, file_mode) in [
            ("group-writable directory", 0o770, 0o600),
            ("group-readable file", 0o700, 0o640),
        ] {
            let directory = TestDirectory::new();
            let namespace = directory.path().join("saltbox");
            let cache_directory = namespace.join("facts");
            let cache_path = cache_directory.join("public-ip.json");
            fs::create_dir(&namespace).unwrap();
            fs::create_dir(&cache_directory).unwrap();
            fs::set_permissions(&namespace, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&cache_directory, fs::Permissions::from_mode(directory_mode))
                .unwrap();
            fs::write(
                &cache_path,
                json!({
                    "version": 1,
                    "ipv4": {"address": "8.8.8.8", "observed_at": 1_780_001_000_u64}
                })
                .to_string(),
            )
            .unwrap();
            fs::set_permissions(&cache_path, fs::Permissions::from_mode(file_mode)).unwrap();
            let server = TestHttpServer::start(|_| ("200 OK", "1.1.1.1", Duration::from_millis(5)));
            let urls = server_urls(&[&server]);
            let urls = url_refs(&urls);

            let (ipv4, _) = resolve_public_ips_with_policy(
                &Client::new(),
                &urls,
                &[],
                false,
                "IPv6 unavailable".to_string(),
                test_lookup_policy(&cache_path, 1_780_001_100),
            )
            .await;

            assert_eq!(
                ipv4,
                (Some("1.1.1.1".to_string()), None),
                "{case} was trusted"
            );
            assert_eq!(server.request_count(), 1, "{case} skipped HTTPS");
            assert_eq!(
                fs::metadata(&cache_directory).unwrap().permissions().mode() & 0o777,
                0o700,
                "{case} directory mode was not repaired"
            );
            assert_eq!(
                fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777,
                0o600,
                "{case} file mode was not repaired"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn writable_cache_namespace_is_ignored_without_mutation() {
        let directory = TestDirectory::new();
        let namespace = directory.path().join("saltbox");
        let cache_directory = namespace.join("facts");
        let cache_path = cache_directory.join("public-ip.json");
        fs::create_dir(&namespace).unwrap();
        fs::create_dir(&cache_directory).unwrap();
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&cache_directory, fs::Permissions::from_mode(0o700)).unwrap();
        let original = json!({
            "version": 1,
            "ipv4": {"address": "8.8.8.8", "observed_at": 1_780_001_000_u64}
        })
        .to_string();
        write_private_cache(&cache_path, &original);
        let server = TestHttpServer::start(|_| ("200 OK", "1.1.1.1", Duration::from_millis(5)));
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let (ipv4, _) = resolve_public_ips_with_policy(
            &Client::new(),
            &urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_100),
        )
        .await;

        assert_eq!(ipv4, (Some("1.1.1.1".to_string()), None));
        assert_eq!(server.request_count(), 1);
        assert_eq!(fs::read_to_string(&cache_path).unwrap(), original);
        assert_eq!(
            fs::metadata(&namespace).unwrap().permissions().mode() & 0o777,
            0o777
        );
        assert!(!cache_directory.join(".public-ip.lock").exists());
    }

    #[test]
    fn cache_metadata_owned_by_another_user_is_rejected() {
        let directory = TestDirectory::new();
        let metadata = fs::metadata(directory.path()).unwrap();
        let other_user = metadata.uid().wrapping_add(1);

        let error = validate_owner(&metadata, other_user).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn missing_cache_directory_is_recreated_and_populated() {
        let directory = TestDirectory::new();
        let cache_directory = directory.path().join("saltbox").join("facts");
        let cache_path = cache_directory.join("public-ip.json");
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.80", Duration::from_millis(5)));
        let ipv4_urls = server_urls(&[&server]);
        let ipv4_urls = url_refs(&ipv4_urls);

        assert!(!cache_directory.exists());

        let (ipv4, _) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_000),
        )
        .await;

        assert_eq!(ipv4, (Some("8.8.4.80".to_string()), None));
        assert!(cache_directory.is_dir());
        let cache: serde_json::Value =
            serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(cache["ipv4"]["address"], "8.8.4.80");
        assert_eq!(cache["ipv4"]["observed_at"], 1_780_001_000_u64);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn symlink_cache_directory_is_a_soft_write_failure() {
        let directory = TestDirectory::new();
        let cache_namespace = directory.path().join("saltbox");
        let redirected_directory = directory.path().join("redirected");
        fs::create_dir(&cache_namespace).unwrap();
        fs::create_dir(&redirected_directory).unwrap();
        let cache_directory = cache_namespace.join("facts");
        symlink(&redirected_directory, &cache_directory).unwrap();
        let cache_path = cache_directory.join("public-ip.json");
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.81", Duration::from_millis(5)));
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

        assert_eq!(ipv4, (Some("8.8.4.81".to_string()), None));
        assert!(fs::symlink_metadata(&cache_directory)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read_dir(&redirected_directory).unwrap().count(), 0);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_cache_behind_symlinked_facts_directory_is_ignored() {
        let directory = TestDirectory::new();
        let cache_namespace = directory.path().join("saltbox");
        let redirected_directory = directory.path().join("redirected");
        fs::create_dir(&cache_namespace).unwrap();
        fs::create_dir(&redirected_directory).unwrap();
        let cache_directory = cache_namespace.join("facts");
        symlink(&redirected_directory, &cache_directory).unwrap();
        let cache_path = cache_directory.join("public-ip.json");
        let redirected_cache_path = redirected_directory.join("public-ip.json");
        let redirected_cache = json!({
            "version": 1,
            "ipv4": {"address": "8.8.4.90", "observed_at": 1_780_001_000_u64}
        })
        .to_string();
        fs::write(&redirected_cache_path, &redirected_cache).unwrap();
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.91", Duration::from_millis(5)));
        let ipv4_urls = server_urls(&[&server]);
        let ipv4_urls = url_refs(&ipv4_urls);

        let (ipv4, _) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_100),
        )
        .await;

        assert_eq!(ipv4, (Some("8.8.4.91".to_string()), None));
        assert_eq!(server.request_count(), 1);
        assert_eq!(
            fs::read_to_string(&redirected_cache_path).unwrap(),
            redirected_cache
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fresh_cache_behind_symlinked_namespace_is_ignored() {
        let directory = TestDirectory::new();
        let redirected_namespace = directory.path().join("redirected");
        let redirected_directory = redirected_namespace.join("facts");
        fs::create_dir(&redirected_namespace).unwrap();
        fs::create_dir(&redirected_directory).unwrap();
        let cache_namespace = directory.path().join("saltbox");
        symlink(&redirected_namespace, &cache_namespace).unwrap();
        let cache_path = cache_namespace.join("facts").join("public-ip.json");
        let redirected_cache_path = redirected_directory.join("public-ip.json");
        let redirected_cache = json!({
            "version": 1,
            "ipv4": {"address": "8.8.4.92", "observed_at": 1_780_001_000_u64}
        })
        .to_string();
        fs::write(&redirected_cache_path, &redirected_cache).unwrap();
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.93", Duration::from_millis(5)));
        let ipv4_urls = server_urls(&[&server]);
        let ipv4_urls = url_refs(&ipv4_urls);

        let (ipv4, _) = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_100),
        )
        .await;

        assert_eq!(ipv4, (Some("8.8.4.93".to_string()), None));
        assert_eq!(server.request_count(), 1);
        assert_eq!(
            fs::read_to_string(&redirected_cache_path).unwrap(),
            redirected_cache
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn recreated_cache_hierarchy_uses_saltbox_directory_modes() {
        let directory = TestDirectory::new();
        let cache_namespace = directory.path().join("saltbox");
        let cache_directory = cache_namespace.join("facts");
        let cache_path = cache_directory.join("public-ip.json");
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.82", Duration::from_millis(5)));
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

        assert_eq!(ipv4, (Some("8.8.4.82".to_string()), None));
        assert_eq!(
            fs::metadata(&cache_namespace).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&cache_directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_artifacts_use_public_ip_names_and_private_modes() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let cache_directory = cache_path.parent().unwrap();
        let lock_path = cache_directory.join(".public-ip.lock");
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.83", Duration::from_millis(5)));
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

        assert_eq!(ipv4, (Some("8.8.4.83".to_string()), None));
        assert_eq!(
            fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut persisted_files = fs::read_dir(cache_directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        persisted_files.sort();
        assert_eq!(persisted_files, [".public-ip.lock", "public-ip.json"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn ipv4_and_ipv6_cache_expiration_refresh_independently() {
        let now = 1_780_001_000;

        let ipv4_directory = TestDirectory::new();
        let ipv4_cache_path = ipv4_directory.cache_path();
        write_private_cache(
            &ipv4_cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "8.8.4.1", "observed_at": now - 900},
                "ipv6": {"address": "2606:4700:4700::1", "observed_at": now - 899}
            })
            .to_string(),
        );
        let ipv4_server =
            TestHttpServer::start(|_| ("200 OK", "8.8.4.2", Duration::from_millis(5)));
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

        assert_eq!(ipv4, (Some("8.8.4.2".to_string()), None));
        assert_eq!(ipv6, (Some("2606:4700:4700::1".to_string()), None));
        assert_eq!(ipv4_server.request_count(), 1);
        assert_eq!(unexpected_ipv6.request_count(), 0);

        let ipv6_directory = TestDirectory::new();
        let ipv6_cache_path = ipv6_directory.cache_path();
        write_private_cache(
            &ipv6_cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "8.8.4.3", "observed_at": now - 899},
                "ipv6": {"address": "2606:4700:4700::3", "observed_at": now - 900}
            })
            .to_string(),
        );
        let unexpected_ipv4 =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let ipv6_server =
            TestHttpServer::start(|_| ("200 OK", "2606:4700:4700::4", Duration::from_millis(5)));
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

        assert_eq!(ipv4, (Some("8.8.4.3".to_string()), None));
        assert_eq!(ipv6, (Some("2606:4700:4700::4".to_string()), None));
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
                    "ipv4": {"address": "8.8.4.10", "observed_at": now}
                })
                .to_string(),
            ),
            (
                "wrong address family",
                json!({
                    "version": 1,
                    "ipv4": {"address": "2606:4700:4700::10", "observed_at": now}
                })
                .to_string(),
            ),
            (
                "expired timestamp",
                json!({
                    "version": 1,
                    "ipv4": {"address": "8.8.4.10", "observed_at": now - 900}
                })
                .to_string(),
            ),
            (
                "future timestamp",
                json!({
                    "version": 1,
                    "ipv4": {"address": "8.8.4.10", "observed_at": now + 1}
                })
                .to_string(),
            ),
        ];

        for (case, cache) in cases {
            let directory = TestDirectory::new();
            let cache_path = directory.cache_path();
            write_private_cache(&cache_path, cache);
            let server =
                TestHttpServer::start(|_| ("200 OK", "8.8.4.99", Duration::from_millis(5)));
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
                (Some("8.8.4.99".to_string()), None),
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
            "ipv4": {"address": "8.8.4.70", "observed_at": now}
        })
        .to_string();

        let boundary_directory = TestDirectory::new();
        let boundary_cache_path = boundary_directory.cache_path();
        let mut boundary_cache = cache_json.as_bytes().to_vec();
        boundary_cache.resize(4096, b' ');
        write_private_cache(&boundary_cache_path, &boundary_cache);
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

        assert_eq!(boundary_ipv4, (Some("8.8.4.70".to_string()), None));
        assert_eq!(unexpected_server.request_count(), 0);

        let oversized_directory = TestDirectory::new();
        let oversized_cache_path = oversized_directory.cache_path();
        let mut oversized_cache = cache_json.into_bytes();
        oversized_cache.resize(4097, b' ');
        write_private_cache(&oversized_cache_path, &oversized_cache);
        let live_server =
            TestHttpServer::start(|_| ("200 OK", "8.8.4.71", Duration::from_millis(5)));
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

        assert_eq!(oversized_ipv4, (Some("8.8.4.71".to_string()), None));
        assert_eq!(live_server.request_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_cache_and_failed_live_lookup_leave_cache_bytes_unchanged() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let original = b"{\n  \"version\": 1,\n  \"ipv4\": {\"address\": \"8.8.4.10\", \"observed_at\": 1779999000}\n}\n";
        write_private_cache(&cache_path, original);
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
            "ipv4": {"address": "8.8.4.10", "observed_at": 1_780_000_000_u64},
            "ipv6": {"address": "2606:4700:4700::10", "observed_at": 1_780_000_000_u64}
        });
        write_private_cache(&cache_path, original_cache.to_string());
        let ipv4_server =
            TestHttpServer::start(|_| ("200 OK", "8.8.4.11", Duration::from_millis(5)));
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

        assert_eq!(ipv4, (Some("8.8.4.11".to_string()), None));
        assert!(ipv6.0.is_none());
        assert!(ipv6.1.unwrap().contains("Attempt 3:"));
        assert_eq!(ipv4_server.request_count(), 1);
        assert_eq!(ipv6_server.request_count(), 3);

        let updated_cache: serde_json::Value =
            serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(
            updated_cache["ipv4"],
            json!({"address": "8.8.4.11", "observed_at": now})
        );
        assert_eq!(updated_cache["ipv6"], original_cache["ipv6"]);
        assert_eq!(updated_cache["ipv6"]["observed_at"], 1_780_000_000_u64);
    }

    #[test]
    fn concurrent_complementary_writers_merge_the_latest_cache() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let lock_path = cache_path.parent().unwrap().join(".public-ip.lock");
        let now = 1_780_001_000;
        let old_cache = json!({
            "version": 1,
            "ipv4": {"address": "8.8.4.10", "observed_at": 1_780_000_000_u64},
            "ipv6": {"address": "2606:4700:4700::10", "observed_at": 1_780_000_000_u64}
        });
        write_private_cache(&cache_path, old_cache.to_string());
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&lock_path)
            .unwrap();
        lock_file.try_lock().unwrap();

        let start = Arc::new(Barrier::new(3));
        let (started_sender, started_receiver) = mpsc::sync_channel(2);
        let ipv4_cache_path = cache_path.clone();
        let ipv4_start = Arc::clone(&start);
        let ipv4_started = started_sender.clone();
        let ipv4_writer = thread::spawn(move || {
            let snapshot = load_cache(&ipv4_cache_path).unwrap();
            assert_eq!(snapshot.ipv4.unwrap().address, "8.8.4.10");
            ipv4_start.wait();
            ipv4_started.send(()).unwrap();
            merge_successful_cache_entries_with_timeout(
                &ipv4_cache_path,
                Some("8.8.4.11".to_string()),
                None,
                now,
                CACHE_LOCK_TIMEOUT,
            )
        });

        let ipv6_cache_path = cache_path.clone();
        let ipv6_start = Arc::clone(&start);
        let ipv6_started = started_sender.clone();
        let ipv6_writer = thread::spawn(move || {
            let snapshot = load_cache(&ipv6_cache_path).unwrap();
            assert_eq!(snapshot.ipv6.unwrap().address, "2606:4700:4700::10");
            ipv6_start.wait();
            ipv6_started.send(()).unwrap();
            merge_successful_cache_entries_with_timeout(
                &ipv6_cache_path,
                None,
                Some("2606:4700:4700::11".to_string()),
                now,
                CACHE_LOCK_TIMEOUT,
            )
        });

        start.wait();
        started_receiver.recv().unwrap();
        started_receiver.recv().unwrap();
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
            json!({"address": "8.8.4.11", "observed_at": now})
        );
        assert_eq!(
            merged["ipv6"],
            json!({"address": "2606:4700:4700::11", "observed_at": now})
        );
        assert!(fs::metadata(&lock_path).unwrap().file_type().is_file());
        assert_eq!(
            fs::metadata(&lock_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn held_cache_lock_times_out_without_changing_live_result() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let lock_path = cache_path.parent().unwrap().join(".public-ip.lock");
        let original_cache = json!({
            "version": 1,
            "ipv4": {"address": "8.8.4.20", "observed_at": 1_780_000_000_u64}
        })
        .to_string();
        write_private_cache(&cache_path, &original_cache);
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&lock_path)
            .unwrap();
        lock_file.try_lock().unwrap();
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.21", Duration::from_millis(5)));
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
        assert_eq!(ipv4, (Some("8.8.4.21".to_string()), None));
        assert!(elapsed >= Duration::from_millis(25), "elapsed: {elapsed:?}");
        assert!(elapsed < Duration::from_millis(250), "elapsed: {elapsed:?}");
        assert_eq!(fs::read_to_string(&cache_path).unwrap(), original_cache);
        assert_eq!(server.request_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn contended_cache_write_does_not_block_the_async_executor() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let lock_path = cache_path.parent().unwrap().join(".public-ip.lock");
        let lock_file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&lock_path)
            .unwrap();
        lock_file.try_lock().unwrap();
        let server = TestHttpServer::start(|_| ("200 OK", "1.1.1.1", Duration::from_millis(5)));
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);
        let client = Client::new();
        let started = Instant::now();

        let (result, timer_elapsed) = tokio::join!(
            resolve_public_ips_with_policy(
                &client,
                &urls,
                &[],
                false,
                "IPv6 unavailable".to_string(),
                test_lookup_policy(&cache_path, 1_780_001_000),
            ),
            async {
                tokio::time::sleep(Duration::from_millis(100)).await;
                started.elapsed()
            }
        );

        lock_file.unlock().unwrap();
        assert_eq!(result.0, (Some("1.1.1.1".to_string()), None));
        assert!(
            timer_elapsed < Duration::from_millis(500),
            "executor was blocked for {timer_elapsed:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn nonregular_lock_targets_are_soft_write_failures() {
        for target_kind in ["directory", "fifo", "symlink"] {
            let directory = TestDirectory::new();
            let cache_path = directory.cache_path();
            let lock_path = cache_path.parent().unwrap().join(".public-ip.lock");
            match target_kind {
                "directory" => fs::create_dir(&lock_path).unwrap(),
                "fifo" => assert!(Command::new("mkfifo")
                    .arg(&lock_path)
                    .status()
                    .unwrap()
                    .success()),
                "symlink" => {
                    let target = directory.path().join("lock-target");
                    fs::write(&target, "do not touch").unwrap();
                    symlink(&target, &lock_path).unwrap();
                }
                _ => unreachable!(),
            }
            let server =
                TestHttpServer::start(|_| ("200 OK", "8.8.4.30", Duration::from_millis(5)));
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
                (Some("8.8.4.30".to_string()), None),
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
        write_private_cache(
            &cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "8.8.4.10", "observed_at": now - 900},
                "ipv6": {"address": "2606:4700:4700::10", "observed_at": now - 899}
            })
            .to_string(),
        );
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.11", Duration::from_millis(5)));
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

        assert_eq!(ipv4, (Some("8.8.4.11".to_string()), None));
        assert_eq!(ipv6, (Some("2606:4700:4700::10".to_string()), None));
        let cache: serde_json::Value =
            serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(cache["ipv4"]["address"], "8.8.4.11");
        assert_eq!(cache["ipv4"]["observed_at"], now);
        assert_eq!(cache["ipv6"]["address"], "2606:4700:4700::10");
        assert_eq!(cache["ipv6"]["observed_at"], now - 899);
        assert_eq!(
            fs::metadata(&cache_path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let mut persisted_files = fs::read_dir(cache_path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        persisted_files.sort();
        assert_eq!(persisted_files, [".public-ip.lock", "public-ip.json"]);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn cache_read_and_write_failure_cannot_hide_live_success() {
        let directory = TestDirectory::new();
        let non_regular_cache_path = directory.cache_path();
        fs::create_dir(&non_regular_cache_path).unwrap();
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.50", Duration::from_millis(5)));
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

        assert_eq!(ipv4, (Some("8.8.4.50".to_string()), None));
        assert!(non_regular_cache_path.is_dir());
    }

    #[test]
    fn fifo_cache_target_is_a_bounded_soft_miss() {
        let directory = TestDirectory::new();
        let fifo_path = directory.cache_path();
        assert!(Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .unwrap()
            .success());
        assert!(fs::symlink_metadata(&fifo_path)
            .unwrap()
            .file_type()
            .is_fifo());
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.4.60", Duration::from_millis(5)));
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
        assert_eq!(ipv4, (Some("8.8.4.60".to_string()), None));
        assert_eq!(server.request_count(), 1);
        assert!(fs::symlink_metadata(&fifo_path)
            .unwrap()
            .file_type()
            .is_fifo());
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

    #[tokio::test(flavor = "current_thread")]
    async fn trusted_echo_responses_accept_syntax_and_family_only() {
        for (address, is_ipv6, canonical) in [
            (" 10.0.0.1\n", false, "10.0.0.1"),
            ("192.88.99.1", false, "192.88.99.1"),
            ("192.88.99.2", false, "192.88.99.2"),
            ("192.0.2.1", false, "192.0.2.1"),
            ("::1", true, "::1"),
            ("2001:db8::1", true, "2001:db8::1"),
        ] {
            let server = TestHttpServer::start(move |_| ("200 OK", address, Duration::ZERO));
            let urls = server_urls(&[&server]);
            let urls = url_refs(&urls);

            assert_eq!(
                get_ip(&Client::new(), &urls, is_ipv6).await,
                (Some(canonical.to_string()), None),
                "rejected trusted {address} response"
            );
        }

        for (address, is_ipv6) in [("not an address", false), ("10.0.0.1", true)] {
            let server = TestHttpServer::start(move |_| ("200 OK", address, Duration::ZERO));
            let urls = server_urls(&[&server]);
            let urls = url_refs(&urls);

            let (result, error) = get_ip(&Client::new(), &urls, is_ipv6).await;
            assert_eq!(result, None, "accepted invalid {address} response");
            assert!(
                error.is_some(),
                "missing error for invalid {address} response"
            );
        }
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
