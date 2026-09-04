use super::address::{canonical_public_ip, AddressFamily};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub(super) const PUBLIC_IP_CACHE_PATH: &str = "/var/cache/saltbox/facts/public-ip.json";
pub(super) const CACHE_LOCK_TIMEOUT: Duration = Duration::from_secs(1);
const CACHE_VERSION: u8 = 1;
const CACHE_TTL_SECONDS: u64 = 900;
const MAX_CACHE_BYTES: usize = 4096;
const CACHE_LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
const CACHE_NAMESPACE_MODE: u32 = 0o755;
const CACHE_DIRECTORY_MODE: u32 = 0o700;
const CACHE_FILE_MODE: u32 = 0o600;
const CACHE_LOCK_FILE_NAME: &str = ".public-ip.lock";
const O_DIRECTORY: i32 = 0o200000;
const O_NONBLOCK: i32 = 0o4000;
const O_NOFOLLOW: i32 = 0o400000;
static CACHE_TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct CacheEntry {
    address: String,
    observed_at: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct PublicIpCache {
    version: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv4: Option<CacheEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ipv6: Option<CacheEntry>,
}

#[derive(Debug, Default)]
pub(super) struct CacheLoadResult {
    pub(super) cache: Option<PublicIpCache>,
    pub(super) warnings: Vec<String>,
}

#[derive(Debug)]
pub(super) struct CacheMergeResult {
    pub(super) read_warnings: Vec<String>,
    pub(super) write_result: io::Result<()>,
}

#[derive(Deserialize)]
struct RawPublicIpCache {
    version: u8,
    #[serde(default)]
    ipv4: Option<Value>,
    #[serde(default)]
    ipv6: Option<Value>,
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

pub(super) fn load(cache_path: &Path, now: u64) -> CacheLoadResult {
    if let Err(error) = validate_cache_parent(cache_path) {
        return if error.kind() == io::ErrorKind::NotFound {
            CacheLoadResult::default()
        } else {
            ignored_cache(error.to_string())
        };
    }
    let cache_file = match OpenOptions::new()
        .read(true)
        .custom_flags(O_NONBLOCK | O_NOFOLLOW)
        .open(cache_path)
    {
        Ok(cache_file) => cache_file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return CacheLoadResult::default();
        }
        Err(error) => {
            let warning = match fs::symlink_metadata(cache_path) {
                Ok(metadata) if !metadata.file_type().is_file() => {
                    "cache target is not a regular file".to_string()
                }
                _ => format!("cache file could not be opened: {error}"),
            };
            return ignored_cache(warning);
        }
    };
    let metadata = match cache_file.metadata() {
        Ok(metadata) => metadata,
        Err(error) => return ignored_cache(format!("cache metadata could not be read: {error}")),
    };
    if !metadata.file_type().is_file() {
        return ignored_cache("cache target is not a regular file");
    }
    if let Err(error) = validate_owner(&metadata, effective_uid()) {
        return ignored_cache(error.to_string());
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        return ignored_cache("cache file permissions are not trusted");
    }
    if metadata.len() > MAX_CACHE_BYTES as u64 {
        return ignored_cache(format!("cache exceeds {MAX_CACHE_BYTES}-byte limit"));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if let Err(error) = cache_file
        .take(MAX_CACHE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
    {
        return ignored_cache(format!("cache content could not be read: {error}"));
    }
    if bytes.len() > MAX_CACHE_BYTES {
        return ignored_cache(format!("cache exceeds {MAX_CACHE_BYTES}-byte limit"));
    }
    let raw: RawPublicIpCache = match serde_json::from_slice(&bytes) {
        Ok(raw) => raw,
        Err(_) => return ignored_cache("malformed cache JSON"),
    };
    if raw.version != CACHE_VERSION {
        return ignored_cache(format!("unsupported cache schema version {}", raw.version));
    }

    let mut warnings = Vec::new();
    let ipv4 = parse_cache_entry(raw.ipv4, AddressFamily::Ipv4, now, &mut warnings);
    let ipv6 = parse_cache_entry(raw.ipv6, AddressFamily::Ipv6, now, &mut warnings);
    CacheLoadResult {
        cache: Some(PublicIpCache {
            version: raw.version,
            ipv4,
            ipv6,
        }),
        warnings,
    }
}

fn ignored_cache(warning: impl Into<String>) -> CacheLoadResult {
    CacheLoadResult {
        cache: None,
        warnings: vec![warning.into()],
    }
}

fn parse_cache_entry(
    value: Option<Value>,
    family: AddressFamily,
    now: u64,
    warnings: &mut Vec<String>,
) -> Option<CacheEntry> {
    let value = value?;
    let mut entry: CacheEntry = match serde_json::from_value(value) {
        Ok(entry) => entry,
        Err(_) => {
            warnings.push(format!("{} cache entry is malformed", family.label()));
            return None;
        }
    };
    let Some(address) = canonical_public_ip(&entry.address, family) else {
        let problem = if entry.address.trim().parse::<IpAddr>().is_ok() {
            "has wrong address family"
        } else {
            "is malformed"
        };
        warnings.push(format!("{} cache entry {problem}", family.label()));
        return None;
    };
    if entry.observed_at > now {
        warnings.push(format!("{} cache entry is future-dated", family.label()));
        return None;
    }
    entry.address = address;
    Some(entry)
}

pub(super) fn fresh_address(
    cache: &PublicIpCache,
    family: AddressFamily,
    now: u64,
) -> Option<String> {
    if cache.version != CACHE_VERSION {
        return None;
    }
    let entry = match family {
        AddressFamily::Ipv4 => cache.ipv4.as_ref(),
        AddressFamily::Ipv6 => cache.ipv6.as_ref(),
    }?;
    let age = now.checked_sub(entry.observed_at)?;
    (age < CACHE_TTL_SECONDS)
        .then(|| canonical_public_ip(&entry.address, family))
        .flatten()
}

fn cache_for_update(cache: Option<PublicIpCache>) -> PublicIpCache {
    let Some(mut cache) = cache.filter(|cache| cache.version == CACHE_VERSION) else {
        return PublicIpCache::default();
    };
    cache.ipv4 = cache
        .ipv4
        .and_then(|entry| canonical_cache_entry(entry, AddressFamily::Ipv4));
    cache.ipv6 = cache
        .ipv6
        .and_then(|entry| canonical_cache_entry(entry, AddressFamily::Ipv6));
    cache
}

fn canonical_cache_entry(mut entry: CacheEntry, family: AddressFamily) -> Option<CacheEntry> {
    entry.address = canonical_public_ip(&entry.address, family)?;
    Some(entry)
}

pub(super) fn merge_successful_entries_with_timeout(
    cache_path: &Path,
    live_ipv4: Option<String>,
    live_ipv6: Option<String>,
    now: u64,
    cache_lock_timeout: Duration,
) -> CacheMergeResult {
    let mut read_warnings = Vec::new();
    let write_result = (|| {
        let parent = cache_path
            .parent()
            .ok_or_else(|| io::Error::other("cache path has no parent directory"))?;
        ensure_cache_parent(cache_path)?;
        let lock_path = parent.join(CACHE_LOCK_FILE_NAME);
        let lock_file = acquire_cache_lock(&lock_path, cache_lock_timeout)?;

        let loaded = load(cache_path, now);
        read_warnings = loaded.warnings;
        let mut cache = cache_for_update(loaded.cache);
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
    })();
    CacheMergeResult {
        read_warnings,
        write_result,
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_ip::test_support::*;
    use crate::public_ip::{resolve_public_ips_with_policy, LookupOutcome, PublicIpResolution};
    use reqwest::Client;
    use serde_json::json;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{symlink, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::process::Command;
    use std::sync::{mpsc, Arc, Barrier};
    use std::thread;
    use std::time::{Duration, Instant};

    fn successful(address: &str) -> LookupOutcome {
        LookupOutcome {
            address: Some(address.to_string()),
            error: None,
        }
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

        let PublicIpResolution { ipv4, ipv6, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_000_899),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.10"));
        assert_eq!(ipv6, successful("2606:4700:4700::10"));
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

            let PublicIpResolution { ipv4, .. } = resolve_public_ips_with_policy(
                &Client::new(),
                &urls,
                &[],
                false,
                "IPv6 unavailable".to_string(),
                test_lookup_policy(&cache_path, 1_780_001_100),
            )
            .await;

            assert_eq!(ipv4, successful("1.1.1.1"), "{case} was trusted");
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

        let PublicIpResolution {
            ipv4,
            cache_warning,
            ..
        } = resolve_public_ips_with_policy(
            &Client::new(),
            &urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_100),
        )
        .await;

        assert_eq!(ipv4, successful("1.1.1.1"));
        assert_eq!(
            cache_warning.as_deref(),
            Some(
                "cache read ignored: cache directory permissions are not trusted | cache write skipped: cache directory permissions are not trusted"
            )
        );
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

        let PublicIpResolution {
            ipv4,
            cache_warning,
            ..
        } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_000),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.80"));
        assert_eq!(cache_warning, None);
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

        let PublicIpResolution { ipv4, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_000),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.81"));
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

        let PublicIpResolution { ipv4, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_100),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.91"));
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

        let PublicIpResolution { ipv4, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_100),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.93"));
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

        let PublicIpResolution { ipv4, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_000),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.82"));
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

        let PublicIpResolution { ipv4, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_000),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.83"));
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

        let PublicIpResolution { ipv4, ipv6, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&ipv4_cache_path, now),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.2"));
        assert_eq!(ipv6, successful("2606:4700:4700::1"));
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

        let PublicIpResolution { ipv4, ipv6, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&ipv6_cache_path, now),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.3"));
        assert_eq!(ipv6, successful("2606:4700:4700::4"));
        assert_eq!(unexpected_ipv4.request_count(), 0);
        assert_eq!(ipv6_server.request_count(), 1);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_cache_variants_are_live_lookup_misses() {
        let now = 1_780_001_000;
        let cases = [
            (
                "malformed JSON",
                "{not json".to_string(),
                Some("cache read ignored: malformed cache JSON"),
            ),
            (
                "unsupported schema",
                json!({
                    "version": 2,
                    "ipv4": {"address": "8.8.4.10", "observed_at": now}
                })
                .to_string(),
                Some("cache read ignored: unsupported cache schema version 2"),
            ),
            (
                "wrong address family",
                json!({
                    "version": 1,
                    "ipv4": {"address": "2606:4700:4700::10", "observed_at": now}
                })
                .to_string(),
                Some("cache read ignored: IPv4 cache entry has wrong address family"),
            ),
            (
                "malformed address",
                json!({
                    "version": 1,
                    "ipv4": {"address": "not-an-address", "observed_at": now}
                })
                .to_string(),
                Some("cache read ignored: IPv4 cache entry is malformed"),
            ),
            (
                "expired timestamp",
                json!({
                    "version": 1,
                    "ipv4": {"address": "8.8.4.10", "observed_at": now - 900}
                })
                .to_string(),
                None,
            ),
            (
                "future timestamp",
                json!({
                    "version": 1,
                    "ipv4": {"address": "8.8.4.10", "observed_at": now + 1}
                })
                .to_string(),
                Some("cache read ignored: IPv4 cache entry is future-dated"),
            ),
        ];

        for (case, cache, expected_warning) in cases {
            let directory = TestDirectory::new();
            let cache_path = directory.cache_path();
            write_private_cache(&cache_path, cache);
            let server =
                TestHttpServer::start(|_| ("200 OK", "8.8.4.99", Duration::from_millis(5)));
            let ipv4_urls = server_urls(&[&server]);
            let ipv4_urls = url_refs(&ipv4_urls);

            let PublicIpResolution {
                ipv4,
                cache_warning,
                ..
            } = resolve_public_ips_with_policy(
                &Client::new(),
                &ipv4_urls,
                &[],
                false,
                "IPv6 unavailable".to_string(),
                test_lookup_policy(&cache_path, now),
            )
            .await;

            assert_eq!(ipv4, successful("8.8.4.99"), "{case} should miss");
            assert_eq!(server.request_count(), 1, "{case} should use HTTP");
            assert_eq!(cache_warning.as_deref(), expected_warning, "{case}");
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

        let PublicIpResolution {
            ipv4: boundary_ipv4,
            ..
        } = resolve_public_ips_with_policy(
            &Client::new(),
            &boundary_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&boundary_cache_path, now),
        )
        .await;

        assert_eq!(boundary_ipv4, successful("8.8.4.70"));
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

        let oversized_resolution = resolve_public_ips_with_policy(
            &Client::new(),
            &oversized_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&oversized_cache_path, now),
        )
        .await;

        let oversized_ipv4 = oversized_resolution.ipv4.clone();
        assert_eq!(oversized_ipv4, successful("8.8.4.71"));
        assert_eq!(live_server.request_count(), 1);
        assert_eq!(
            oversized_resolution.cache_warning.as_deref(),
            Some("cache read ignored: cache exceeds 4096-byte limit")
        );
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

        let PublicIpResolution { ipv4, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_000),
        )
        .await;

        assert!(ipv4.address.is_none());
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

        let PublicIpResolution { ipv4, ipv6, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, now),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.11"));
        assert!(ipv6.address.is_none());
        assert!(ipv6.error.unwrap().contains("Attempt 3:"));
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
            let snapshot = load(&ipv4_cache_path, now).cache.unwrap();
            assert_eq!(snapshot.ipv4.unwrap().address, "8.8.4.10");
            ipv4_start.wait();
            ipv4_started.send(()).unwrap();
            merge_successful_entries_with_timeout(
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
            let snapshot = load(&ipv6_cache_path, now).cache.unwrap();
            assert_eq!(snapshot.ipv6.unwrap().address, "2606:4700:4700::10");
            ipv6_start.wait();
            ipv6_started.send(()).unwrap();
            merge_successful_entries_with_timeout(
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

        ipv4_writer.join().unwrap().write_result.unwrap();
        ipv6_writer.join().unwrap().write_result.unwrap();

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

        let (resolution, elapsed) = received.expect("lock acquisition must time out");
        assert_eq!(resolution.ipv4, successful("8.8.4.21"));
        assert_eq!(
            resolution.cache_warning.as_deref(),
            Some("cache write skipped: timed out acquiring cache lock")
        );
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
        assert_eq!(result.ipv4, successful("1.1.1.1"));
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

            let PublicIpResolution { ipv4, .. } = resolve_public_ips_with_policy(
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
                successful("8.8.4.30"),
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

        let PublicIpResolution { ipv4, ipv6, .. } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, now),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.11"));
        assert_eq!(ipv6, successful("2606:4700:4700::10"));
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

        let PublicIpResolution {
            ipv4,
            cache_warning,
            ..
        } = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&non_regular_cache_path, 1_780_001_000),
        )
        .await;

        assert_eq!(ipv4, successful("8.8.4.50"));
        assert_eq!(
            cache_warning.as_deref(),
            Some(
                "cache read ignored: cache target is not a regular file | cache write skipped: cache target is not a regular file"
            )
        );
        assert!(non_regular_cache_path.is_dir());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn invalid_family_entry_warns_without_discarding_valid_other_family() {
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let now = 1_780_001_000;
        write_private_cache(
            &cache_path,
            json!({
                "version": 1,
                "ipv4": {"address": "2606:4700:4700::20", "observed_at": now},
                "ipv6": {"address": "2606:4700:4700::21", "observed_at": now}
            })
            .to_string(),
        );
        let ipv4_server =
            TestHttpServer::start(|_| ("200 OK", "8.8.4.20", Duration::from_millis(5)));
        let unexpected_ipv6 =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let ipv4_urls = server_urls(&[&ipv4_server]);
        let ipv6_urls = server_urls(&[&unexpected_ipv6]);
        let ipv4_urls = url_refs(&ipv4_urls);
        let ipv6_urls = url_refs(&ipv6_urls);

        let first = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, now),
        )
        .await;

        assert_eq!(first.ipv4, successful("8.8.4.20"));
        assert_eq!(first.ipv6, successful("2606:4700:4700::21"));
        assert_eq!(ipv4_server.request_count(), 1);
        assert_eq!(unexpected_ipv6.request_count(), 0);
        assert_eq!(
            first.cache_warning.as_deref(),
            Some("cache read ignored: IPv4 cache entry has wrong address family")
        );

        let unexpected_ipv4 =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let unexpected_ipv6 =
            TestHttpServer::start(|_| ("500 Internal Server Error", "unexpected", Duration::ZERO));
        let ipv4_urls = server_urls(&[&unexpected_ipv4]);
        let ipv6_urls = server_urls(&[&unexpected_ipv6]);
        let ipv4_urls = url_refs(&ipv4_urls);
        let ipv6_urls = url_refs(&ipv6_urls);

        let second = resolve_public_ips_with_policy(
            &Client::new(),
            &ipv4_urls,
            &ipv6_urls,
            true,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, now + 1),
        )
        .await;

        assert_eq!(second.ipv4, successful("8.8.4.20"));
        assert_eq!(second.ipv6, successful("2606:4700:4700::21"));
        assert_eq!(unexpected_ipv4.request_count(), 0);
        assert_eq!(unexpected_ipv6.request_count(), 0);
        assert_eq!(second.cache_warning, None);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn locked_reload_warning_survives_successful_cache_repair() {
        // Catches dropping warnings from the writer's under-lock cache reload.
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let handler_cache_path = cache_path.clone();
        let server = TestHttpServer::start_with_handler(move |stream, _| {
            write_private_cache(&handler_cache_path, "{not json");
            handle_test_request(stream, ("200 OK", "8.8.4.22", Duration::ZERO));
        });
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);
        let now = 1_780_001_000;

        let resolution = resolve_public_ips_with_policy(
            &Client::new(),
            &urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, now),
        )
        .await;

        assert_eq!(resolution.ipv4, successful("8.8.4.22"));
        assert_eq!(
            resolution.cache_warning.as_deref(),
            Some("cache read ignored: malformed cache JSON")
        );
        let repaired: serde_json::Value =
            serde_json::from_slice(&fs::read(&cache_path).unwrap()).unwrap();
        assert_eq!(
            repaired["ipv4"],
            json!({"address": "8.8.4.22", "observed_at": now})
        );
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

        let resolution = receiver
            .recv_timeout(Duration::from_secs(1))
            .expect("FIFO cache resolution must not block");
        assert_eq!(resolution.ipv4, successful("8.8.4.60"));
        assert_eq!(server.request_count(), 1);
        assert!(fs::symlink_metadata(&fifo_path)
            .unwrap()
            .file_type()
            .is_fifo());
    }
}
