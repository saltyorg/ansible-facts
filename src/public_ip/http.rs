use super::address::{canonical_public_ip, AddressFamily};
use super::LookupOutcome;
use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::TryStreamExt;
use reqwest::Client;
use std::time::Duration;
use tokio::time::timeout;

pub(super) const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
pub(super) const RETRY_DELAYS: [Duration; 2] =
    [Duration::from_millis(250), Duration::from_millis(750)];
const MAX_IP_RESPONSE_BYTES: u64 = 64;

pub(super) async fn lookup_with_timeout(
    client: &Client,
    urls: &[&str],
    family: AddressFamily,
    request_timeout: Duration,
) -> LookupOutcome {
    if urls.is_empty() {
        return LookupOutcome {
            address: None,
            error: Some("All requests failed with unknown errors".to_string()),
        };
    }

    let mut errors = vec![None; urls.len()];
    let mut requests = FuturesUnordered::new();

    for (index, &url) in urls.iter().enumerate() {
        requests.push(async move {
            (
                index,
                fetch_ip_from_url(client, url, family, request_timeout).await,
            )
        });
    }

    while let Some((index, result)) = requests.next().await {
        match result {
            Ok(address) => {
                return LookupOutcome {
                    address: Some(address),
                    error: None,
                };
            }
            Err(error) => errors[index] = Some(error),
        }
    }

    let combined_error = if errors.iter().all(Option::is_none) {
        "All requests failed with unknown errors".to_string()
    } else {
        errors.into_iter().flatten().collect::<Vec<_>>().join("; ")
    };

    LookupOutcome {
        address: None,
        error: Some(combined_error),
    }
}

pub(super) async fn lookup_with_retry(
    client: &Client,
    urls: &[&str],
    family: AddressFamily,
    retry_delays: [Duration; 2],
    request_timeout: Duration,
) -> LookupOutcome {
    let mut attempt_errors = Vec::with_capacity(3);

    for attempt in 0..3 {
        let outcome = lookup_with_timeout(client, urls, family, request_timeout).await;
        if outcome.address.is_some() {
            return outcome;
        }

        attempt_errors.push(format!(
            "Attempt {}: {}",
            attempt + 1,
            outcome
                .error
                .unwrap_or_else(|| "All requests failed with unknown errors".to_string())
        ));
        if let Some(delay) = retry_delays.get(attempt) {
            tokio::time::sleep(*delay).await;
        }
    }

    LookupOutcome {
        address: None,
        error: Some(attempt_errors.join(" | ")),
    }
}

async fn fetch_ip_from_url(
    client: &Client,
    url: &str,
    family: AddressFamily,
    request_timeout: Duration,
) -> Result<String, String> {
    match timeout(request_timeout, async {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|error| format!("Request failed for {url}: {error}"))?;
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
            .map_err(|error| format!("Failed to read response body from {url}: {error}"))?
        {
            if bytes.len() + chunk.len() > MAX_IP_RESPONSE_BYTES as usize {
                return Err(format!("Response body from {url} exceeded 64 bytes"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let ip = String::from_utf8(bytes)
            .map_err(|error| format!("Response body from {url} was not valid UTF-8: {error}"))?;
        let ip = ip.trim();
        canonical_public_ip(ip, family).ok_or_else(|| {
            format!(
                "Invalid {} address '{ip}' received from {url}",
                family.label()
            )
        })
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_ip::test_support::*;
    use crate::public_ip::{resolve_public_ips_with_policy, LookupOutcome};
    use reqwest::Client;
    use std::sync::{mpsc, Arc, Mutex};
    use std::time::Duration;

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

        let outcome =
            lookup_with_timeout(&Client::new(), &urls, AddressFamily::Ipv4, REQUEST_TIMEOUT).await;

        assert_eq!(outcome.address, None);
        assert!(outcome.error.unwrap().contains("exceeded 64 bytes"));
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

        let outcome =
            lookup_with_timeout(&Client::new(), &urls, AddressFamily::Ipv4, REQUEST_TIMEOUT).await;

        assert_eq!(outcome.address, None);
        assert!(outcome.error.unwrap().contains("exceeded 64 bytes"));
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

        let outcome =
            lookup_with_timeout(&Client::new(), &urls, AddressFamily::Ipv4, REQUEST_TIMEOUT).await;

        assert_eq!(outcome.address, None);
        assert!(outcome.error.unwrap().contains("not valid UTF-8"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_success_status_is_rejected_without_accepting_its_body() {
        // Catches accepting a syntactically valid body without enforcing HTTP success.
        let server =
            TestHttpServer::start(|_| ("503 Service Unavailable", "8.8.8.8", Duration::ZERO));
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let outcome =
            lookup_with_timeout(&Client::new(), &urls, AddressFamily::Ipv4, REQUEST_TIMEOUT).await;

        assert_eq!(outcome.address, None);
        assert!(outcome.error.unwrap().contains("HTTP 503"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn response_with_wrong_address_family_is_rejected() {
        // Catches accepting any parseable address instead of the requested family.
        let server = TestHttpServer::start(|_| ("200 OK", "2606:4700:4700::1111", Duration::ZERO));
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let outcome =
            lookup_with_timeout(&Client::new(), &urls, AddressFamily::Ipv4, REQUEST_TIMEOUT).await;

        assert_eq!(outcome.address, None);
        assert!(outcome.error.unwrap().contains("Invalid IPv4 address"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn request_timeout_uses_the_private_millisecond_policy() {
        // Catches hard-coding the three-second production timeout in resolver calls.
        let directory = TestDirectory::new();
        let cache_path = directory.cache_path();
        let server = TestHttpServer::start(|_| ("200 OK", "8.8.8.8", Duration::from_millis(100)));
        let urls = server_urls(&[&server]);
        let urls = url_refs(&urls);

        let resolution = resolve_public_ips_with_policy(
            &Client::new(),
            &urls,
            &[],
            false,
            "IPv6 unavailable".to_string(),
            test_lookup_policy(&cache_path, 1_780_001_000),
        )
        .await;

        assert_eq!(resolution.ipv4.address, None);
        assert!(resolution
            .ipv4
            .error
            .unwrap()
            .contains("Timeout after 25ms"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn one_failed_endpoint_and_one_successful_endpoint_do_not_retry() {
        let failure =
            TestHttpServer::start(|_| ("503 Service Unavailable", "unavailable", Duration::ZERO));
        let success =
            TestHttpServer::start(|_| ("200 OK", "8.8.4.10\n", Duration::from_millis(10)));
        let urls = server_urls(&[&failure, &success]);
        let urls = url_refs(&urls);

        let result = lookup_with_retry(
            &Client::new(),
            &urls,
            AddressFamily::Ipv4,
            [Duration::ZERO, Duration::ZERO],
            REQUEST_TIMEOUT,
        )
        .await;

        assert_eq!(
            result,
            LookupOutcome {
                address: Some("8.8.4.10".to_string()),
                error: None
            }
        );
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

        let result = lookup_with_retry(
            &Client::new(),
            &urls,
            AddressFamily::Ipv4,
            [Duration::ZERO, Duration::ZERO],
            REQUEST_TIMEOUT,
        )
        .await;

        assert_eq!(
            result,
            LookupOutcome {
                address: Some("8.8.4.20".to_string()),
                error: None
            }
        );
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

        let outcome = lookup_with_retry(
            &Client::new(),
            &urls,
            AddressFamily::Ipv4,
            [Duration::ZERO, Duration::ZERO],
            REQUEST_TIMEOUT,
        )
        .await;

        assert_eq!(outcome.address, None);
        let error = outcome.error.unwrap();
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

        let outcome =
            lookup_with_timeout(&Client::new(), &urls, AddressFamily::Ipv4, REQUEST_TIMEOUT).await;

        let error = outcome.error.unwrap();
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
            lookup_with_timeout(&Client::new(), &urls, AddressFamily::Ipv4, REQUEST_TIMEOUT).await
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

        assert_eq!(
            result,
            LookupOutcome {
                address: Some("8.8.8.8".to_string()),
                error: None
            }
        );
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

        let result =
            lookup_with_timeout(&Client::new(), &urls, AddressFamily::Ipv6, REQUEST_TIMEOUT).await;

        assert_eq!(
            result,
            LookupOutcome {
                address: Some("2606:4700:4700::1111".to_string()),
                error: None
            }
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn trusted_echo_responses_accept_syntax_and_family_only() {
        for (address, family, canonical) in [
            (" 10.0.0.1\n", AddressFamily::Ipv4, "10.0.0.1"),
            ("192.88.99.1", AddressFamily::Ipv4, "192.88.99.1"),
            ("192.88.99.2", AddressFamily::Ipv4, "192.88.99.2"),
            ("192.0.2.1", AddressFamily::Ipv4, "192.0.2.1"),
            ("::1", AddressFamily::Ipv6, "::1"),
            ("2001:db8::1", AddressFamily::Ipv6, "2001:db8::1"),
        ] {
            let server = TestHttpServer::start(move |_| ("200 OK", address, Duration::ZERO));
            let urls = server_urls(&[&server]);
            let urls = url_refs(&urls);

            assert_eq!(
                lookup_with_timeout(&Client::new(), &urls, family, REQUEST_TIMEOUT).await,
                LookupOutcome {
                    address: Some(canonical.to_string()),
                    error: None
                },
                "rejected trusted {address} response"
            );
        }

        for (address, family) in [
            ("not an address", AddressFamily::Ipv4),
            ("10.0.0.1", AddressFamily::Ipv6),
        ] {
            let server = TestHttpServer::start(move |_| ("200 OK", address, Duration::ZERO));
            let urls = server_urls(&[&server]);
            let urls = url_refs(&urls);

            let outcome = lookup_with_timeout(&Client::new(), &urls, family, REQUEST_TIMEOUT).await;
            assert_eq!(outcome.address, None, "accepted invalid {address} response");
            assert!(
                outcome.error.is_some(),
                "missing error for invalid {address} response"
            );
        }
    }
}
