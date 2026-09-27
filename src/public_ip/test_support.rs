use super::{CacheValidationClock, LookupPolicy};
use reqwest::Client;
use std::fs;
use std::future::Future;
use std::io::{self, BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[path = "../../tests/support/process.rs"]
mod process;

// A hang safeguard, never a performance assertion or a way to order events.
pub(super) use process::TEST_TIMEOUT;

pub(super) fn test_client() -> Client {
    Client::builder().no_proxy().build().unwrap()
}

pub(super) fn run_test_in_subprocess(name: &str) -> bool {
    const CHILD_TEST: &str = "SALTBOX_FACTS_CHILD_TEST";
    if std::env::var(CHILD_TEST).as_deref() == Ok(name) {
        return false;
    }
    // The parent owns the temporary tree even if a hung child must be killed.
    let temporary = tempfile::tempdir().unwrap();
    let output = process::output(
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(CHILD_TEST, name)
            .env("TMPDIR", temporary.path()),
    );
    assert!(
        output.status.success(),
        "child test {name}: status={}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    true
}

pub(super) async fn within_test_deadline<T>(future: impl Future<Output = T>) -> T {
    let (cancel, waiting) = mpsc::channel::<()>();
    // Real time also bounds tests using paused Tokio time. An active blocking
    // task prevents Tokio from auto-advancing while real socket I/O is pending.
    let mut watchdog = tokio::task::spawn_blocking(move || waiting.recv_timeout(TEST_TIMEOUT));
    tokio::select! {
        value = future => {
            drop(cancel);
            let _ = watchdog.await.unwrap();
            value
        }
        result = &mut watchdog => panic!("test exceeded {TEST_TIMEOUT:?} real-time safeguard: {result:?}"),
    }
}

#[derive(Clone)]
pub(super) struct TestSignal {
    name: &'static str,
    state: Arc<(Mutex<bool>, Condvar)>,
}

impl TestSignal {
    pub(super) fn new(name: &'static str) -> Self {
        Self {
            name,
            state: Arc::new((Mutex::new(false), Condvar::new())),
        }
    }

    pub(super) fn notify(&self) {
        *self.state.0.lock().unwrap() = true;
        self.state.1.notify_all();
    }

    fn wait_until(&self, cancelled: impl Fn() -> bool) -> bool {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut ready = self.state.0.lock().unwrap();
        while !*ready {
            if cancelled() {
                return false;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for fixture signal: {}",
                self.name
            );
            // Periodically observe fixture shutdown; readiness comes only from notify.
            ready = self
                .state
                .1
                .wait_timeout(ready, remaining.min(Duration::from_millis(10)))
                .unwrap()
                .0;
        }
        true
    }

    pub(super) fn wait_blocking(&self) {
        assert!(self.wait_until(|| false));
    }

    pub(super) async fn wait(&self) {
        let signal = self.clone();
        tokio::task::spawn_blocking(move || signal.wait_blocking())
            .await
            .unwrap();
    }
}

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
        fs::create_dir_all(&cache_directory).unwrap();
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(&cache_directory, fs::Permissions::from_mode(0o700)).unwrap();
        cache_directory.join("public-ip.json")
    }
}

pub(super) fn write_private_cache(path: &Path, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

struct ServerState {
    address: std::net::SocketAddr,
    accepted: TestSignal,
    started: Instant,
    events: Mutex<Vec<String>>,
    requests: AtomicUsize,
    shutdown: AtomicBool,
    connections: Mutex<Vec<TcpStream>>,
}

impl ServerState {
    fn record(&self, event: impl AsRef<str>) {
        let event = format!("{:?}: {}", self.started.elapsed(), event.as_ref());
        // libtest captures this on success and includes it with a failed test,
        // including cancellation through select!, where Drop is not unwinding.
        eprintln!("[test HTTP {}] {event}", self.address);
        self.events.lock().unwrap().push(event);
    }

    fn stopped(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }
}

pub(super) struct TestRequest {
    stream: TcpStream,
    state: Arc<ServerState>,
    number: usize,
}

impl TestRequest {
    pub(super) fn record(&self, event: &str) {
        self.state
            .record(format!("request {}: {event}", self.number));
    }

    pub(super) fn wait_for(&self, signal: &TestSignal) -> bool {
        self.record(&format!("waiting for {}", signal.name));
        let released = signal.wait_until(|| self.state.stopped());
        self.record(if released {
            "gate released"
        } else {
            "gate cancelled by teardown"
        });
        released
    }

    pub(super) fn respond(self, status: &str, body: &str) {
        self.respond_raw(
            status,
            &[("Content-Length", &body.len().to_string())],
            &[body.as_bytes()],
        );
    }

    pub(super) fn respond_raw(mut self, status: &str, headers: &[(&str, &str)], chunks: &[&[u8]]) {
        let mut response = Vec::new();
        write!(response, "HTTP/1.1 {status}\r\nConnection: close\r\n").unwrap();
        for (name, value) in headers {
            write!(response, "{name}: {value}\r\n").unwrap();
        }
        response.extend_from_slice(b"\r\n");
        let chunked = headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("Transfer-Encoding") && *value == "chunked"
        });
        for chunk in chunks {
            if chunked {
                write!(response, "{:X}\r\n", chunk.len()).unwrap();
            }
            response.extend_from_slice(chunk);
            if chunked {
                response.extend_from_slice(b"\r\n");
            }
        }
        if chunked {
            response.extend_from_slice(b"0\r\n\r\n");
        }
        self.write_response(&response);
    }

    pub(super) fn write_response(&mut self, response: &[u8]) {
        self.record(&format!("sending {} response bytes", response.len()));
        match self.stream.write_all(response) {
            Ok(()) => self.record("response sent"),
            Err(error) if disconnected(&error) => {
                self.record(&format!("client cancelled response: {error}"))
            }
            Err(error) => panic!("fixture response write failed: {error}"),
        }
    }
}

fn disconnected(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::NotConnected
    )
}

pub(super) struct TestHttpServer {
    pub(super) url: String,
    state: Arc<ServerState>,
    thread: Option<JoinHandle<Vec<String>>>,
}

impl TestHttpServer {
    pub(super) fn start<F>(response: F) -> Self
    where
        F: Fn(usize) -> (&'static str, &'static str) + Send + Sync + 'static,
    {
        Self::start_with_handler(move |request, number| {
            let (status, body) = response(number);
            request.respond(status, body);
        })
    }

    pub(super) fn start_with_handler<F>(handler: F) -> Self
    where
        F: Fn(TestRequest, usize) + Send + Sync + 'static,
    {
        Self::with_read_timeout(handler, Some(TEST_TIMEOUT))
    }

    fn with_read_timeout<F>(handler: F, read_timeout: Option<Duration>) -> Self
    where
        F: Fn(TestRequest, usize) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let state = Arc::new(ServerState {
            address,
            accepted: TestSignal::new("fixture accepted connection"),
            started: Instant::now(),
            events: Mutex::new(Vec::new()),
            requests: AtomicUsize::new(0),
            shutdown: AtomicBool::new(false),
            connections: Mutex::new(Vec::new()),
        });
        state.record("listening");
        let thread_state = Arc::clone(&state);
        let handler = Arc::new(handler);
        let thread = thread::spawn(move || {
            let mut workers = Vec::new();
            let mut failures = Vec::new();
            while !thread_state.stopped() {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let mut connections = thread_state.connections.lock().unwrap();
                        if thread_state.stopped() {
                            break;
                        }
                        connections.push(stream.try_clone().unwrap());
                        drop(connections);
                        let state = Arc::clone(&thread_state);
                        let handler = Arc::clone(&handler);
                        workers.push(thread::spawn(move || {
                            state.record("connection accepted; reading request headers");
                            stream.set_read_timeout(read_timeout).unwrap();
                            stream.set_write_timeout(Some(TEST_TIMEOUT)).unwrap();
                            state.accepted.notify();
                            let mut reader = BufReader::new(&stream);
                            let mut line = String::new();
                            loop {
                                line.clear();
                                match reader.read_line(&mut line) {
                                    Ok(0) => {
                                        state.record("client closed before complete headers");
                                        return;
                                    }
                                    Ok(_) if line == "\r\n" => break,
                                    Ok(_) => {}
                                    Err(error) if state.stopped() || disconnected(&error) => {
                                        state.record(format!(
                                            "request cancelled while reading headers: {error}"
                                        ));
                                        return;
                                    }
                                    Err(error) => {
                                        panic!("fixture request header read failed: {error}")
                                    }
                                }
                            }
                            let number = state.requests.fetch_add(1, Ordering::SeqCst) + 1;
                            state.record(format!(
                                "request {number}: headers received; entering handler"
                            ));
                            handler(
                                TestRequest {
                                    stream,
                                    state: Arc::clone(&state),
                                    number,
                                },
                                number,
                            );
                            state.record(format!("request {number}: handler finished"));
                        }));
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::park_timeout(Duration::from_millis(1))
                    }
                    Err(error) => {
                        failures.push(format!("fixture accept failed: {error}"));
                        break;
                    }
                }
            }
            for worker in workers {
                if let Err(error) = worker.join() {
                    failures.push(
                        error
                            .downcast_ref::<String>()
                            .cloned()
                            .or_else(|| error.downcast_ref::<&str>().map(|s| s.to_string()))
                            .unwrap_or_else(|| "fixture worker panicked".to_string()),
                    );
                }
            }
            failures
        });
        Self {
            url: format!("http://{address}"),
            state,
            thread: Some(thread),
        }
    }

    pub(super) fn request_count(&self) -> usize {
        self.state.requests.load(Ordering::SeqCst)
    }

    pub(super) fn diagnostics(&self) -> String {
        format!(
            "HTTP fixture {} ({} complete requests):\n{}",
            self.url,
            self.request_count(),
            self.state.events.lock().unwrap().join("\n")
        )
    }
}

impl Drop for TestHttpServer {
    fn drop(&mut self) {
        self.state.shutdown.store(true, Ordering::SeqCst);
        for stream in self.state.connections.lock().unwrap().iter() {
            let _ = stream.shutdown(Shutdown::Both);
        }
        let thread = self.thread.take().unwrap();
        thread.thread().unpark();
        let failures = thread
            .join()
            .unwrap_or_else(|_| vec!["fixture accept thread panicked".to_string()]);
        if thread::panicking() {
            eprintln!("{}\nworker failures: {failures:?}", self.diagnostics());
        } else {
            assert!(
                failures.is_empty(),
                "{}\nworker failures: {failures:?}",
                self.diagnostics()
            );
        }
    }
}

pub(super) fn server_urls(servers: &[&TestHttpServer]) -> Vec<String> {
    servers.iter().map(|server| server.url.clone()).collect()
}

pub(super) fn url_refs(urls: &[String]) -> Vec<&str> {
    urls.iter().map(String::as_str).collect()
}

pub(super) fn test_lookup_policy(cache_path: &Path, now: u64) -> LookupPolicy<'_> {
    test_lookup_policy_with_reload_time(cache_path, now, now)
}

pub(super) fn test_lookup_policy_with_reload_time(
    cache_path: &Path,
    observed_at: u64,
    reload_validation_time: u64,
) -> LookupPolicy<'_> {
    LookupPolicy {
        cache_path,
        observed_at,
        reload_validation_clock: CacheValidationClock::Fixed(reload_validation_time),
        retry_delays: [Duration::ZERO, Duration::ZERO],
        request_timeout: TEST_TIMEOUT,
        cache_lock_timeout: TEST_TIMEOUT,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teardown_cancels_an_incomplete_http_request() {
        if run_test_in_subprocess(
            "public_ip::test_support::tests::teardown_cancels_an_incomplete_http_request",
        ) {
            return;
        }
        // Disable the fallback before the worker starts reading. Otherwise its
        // own timeout could mask missing cancellation during teardown.
        let server = TestHttpServer::with_read_timeout(
            |request, _| request.respond("200 OK", "unused"),
            None,
        );
        let mut connection = TcpStream::connect(server.url.trim_start_matches("http://")).unwrap();
        connection.write_all(b"GET / HTTP/1.1\r\n").unwrap();
        server.state.accepted.wait_blocking();
        drop(server);
        // The client remains open until after teardown, so EOF cannot rescue an
        // unbounded header read. The parent kills a broken fixture implementation.
        drop(connection);
    }

    #[test]
    fn teardown_cancels_a_handler_waiting_for_an_event() {
        if run_test_in_subprocess(
            "public_ip::test_support::tests::teardown_cancels_a_handler_waiting_for_an_event",
        ) {
            return;
        }
        let entered = TestSignal::new("handler entered");
        let notify_entered = entered.clone();
        let never_released = TestSignal::new("intentionally unreleased response");
        let server = TestHttpServer::start_with_handler(move |request, _| {
            notify_entered.notify();
            request.wait_for(&never_released);
        });
        let mut connection = TcpStream::connect(server.url.trim_start_matches("http://")).unwrap();
        connection
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        entered.wait_blocking();
        let state = Arc::clone(&server.state);
        drop(server);
        assert!(state
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.contains("gate cancelled by teardown")));
    }

    #[test]
    fn worker_failure_does_not_replace_the_original_test_panic() {
        if run_test_in_subprocess("public_ip::test_support::tests::worker_failure_does_not_replace_the_original_test_panic") { return; }
        let result = std::panic::catch_unwind(|| {
            let entered = TestSignal::new("failing handler entered");
            let notify_entered = entered.clone();
            let server = TestHttpServer::start_with_handler(move |request, _| {
                request.record("cache fixture checkpoint");
                notify_entered.notify();
                panic!("secondary worker failure");
            });
            let mut connection =
                TcpStream::connect(server.url.trim_start_matches("http://")).unwrap();
            connection
                .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .unwrap();
            entered.wait_blocking();
            assert!(server.diagnostics().contains("cache fixture checkpoint"));
            panic!("original assertion failure");
        })
        .unwrap_err();
        assert_eq!(
            result.downcast_ref::<&str>(),
            Some(&"original assertion failure")
        );
    }
}
