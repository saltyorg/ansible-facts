use futures_util::stream::{FuturesUnordered, StreamExt};
use reqwest::Client;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

const TIMEOUT: u64 = 3;
const IPV4_URLS: [&str; 2] = ["https://ipify.saltbox.dev", "https://ipv4.icanhazip.com"];
const IPV6_URLS: [&str; 2] = ["https://ipify6.saltbox.dev", "https://ipv6.icanhazip.com"];
const GROUP_FILE_PATH: &str = "/etc/group";
const PASSWD_FILE_PATH: &str = "/etc/passwd";
const IF_INET6_FILE_PATH: &str = "/proc/net/if_inet6";
const ETC_TIMEZONE_PATH: &str = "/etc/timezone";
const LOCALTIME_PATH: &str = "/etc/localtime";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Serialize)]
struct Output<'a> {
    saltbox_facts_version: &'a str,
    ip: IpOutput,
    groups: HashMap<String, GroupData>,
    users: HashMap<String, UserData>,
    timezone: TimezoneData,
}

#[derive(Serialize)]
struct IpOutput {
    public_ip: String,
    public_ipv6: String,
    error_ipv4: Option<String>,
    error_ipv6: Option<String>,
    failed_ipv4: bool,
    failed_ipv6: bool,
    ipv6_check_error: Option<String>,
}

#[derive(Serialize)]
struct GroupData {
    gid: String,
    #[serde(rename = "group-list")]
    group_list: Vec<String>,
}

#[derive(Serialize)]
struct UserData {
    uid: String,
    gid: String,
    comment: String,
    home: String,
    shell: String,
}

#[derive(Serialize)]
struct TimezoneData {
    timezone: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    let groups_handle = tokio::task::spawn_blocking(|| parse_groups(GROUP_FILE_PATH));
    let users_handle = tokio::task::spawn_blocking(|| parse_users(PASSWD_FILE_PATH));
    let timezone_handle = tokio::task::spawn_blocking(get_timezone);

    let ip_future = async {
        let (ipv6_present, ipv6_check_error) = has_valid_ipv6();
        let ((ipv4, ipv4_error), (ipv6, ipv6_error)) = if ipv6_present {
            tokio::join!(
                get_ip(&client, &IPV4_URLS, false),
                get_ip(&client, &IPV6_URLS, true)
            )
        } else {
            (get_ip(&client, &IPV4_URLS, false).await, (None, None))
        };
        ((ipv4, ipv4_error), (ipv6, ipv6_error), ipv6_check_error)
    };

    let (
        ((ipv4, ipv4_error), (ipv6, ipv6_error), ipv6_check_error),
        groups_result,
        users_result,
        timezone_result,
    ) = tokio::join!(ip_future, groups_handle, users_handle, timezone_handle);

    let groups_data =
        groups_result.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })??;
    let users_data = users_result.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })??;
    let timezone_data =
        timezone_result.map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;

    let failed_ipv4 = ipv4.is_none();
    let failed_ipv6 = ipv6.is_none();

    let result = Output {
        saltbox_facts_version: VERSION,
        ip: IpOutput {
            public_ip: ipv4.unwrap_or_default(),
            public_ipv6: ipv6.unwrap_or_default(),
            error_ipv4: ipv4_error,
            error_ipv6: ipv6_error,
            failed_ipv4,
            failed_ipv6,
            ipv6_check_error,
        },
        groups: groups_data,
        users: users_data,
        timezone: timezone_data,
    };

    let sorted_result = sort_json_value(serde_json::to_value(&result)?);
    println!("{}", serde_json::to_string(&sorted_result)?);
    Ok(())
}

fn sort_json_value(value: serde_json::Value) -> serde_json::Value {
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

async fn get_ip(client: &Client, urls: &[&str], is_ipv6: bool) -> (Option<String>, Option<String>) {
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

async fn fetch_ip_from_url(client: &Client, url: &str, is_ipv6: bool) -> Result<String, String> {
    let ip_label = if is_ipv6 { "IPv6" } else { "IPv4" };
    match timeout(Duration::from_secs(TIMEOUT), async {
        let response = client
            .get(url)
            .send()
            .await
            .map_err(|e| format!("Request failed for {}: {}", url, e))?;
        if !response.status().is_success() {
            return Err(format!("HTTP {} received from {}", response.status(), url));
        }
        let ip = response
            .text()
            .await
            .map_err(|e| format!("Failed to read response body from {}: {}", url, e))?;
        let ip = ip.trim();
        if validate_ip(ip, is_ipv6) {
            Ok(ip.to_string())
        } else {
            Err(format!(
                "Invalid {} address '{}' received from {}",
                ip_label, ip, url
            ))
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(format!("Timeout after {}s for {}", TIMEOUT, url)),
    }
}

fn validate_ip(ip: &str, is_ipv6: bool) -> bool {
    if is_ipv6 {
        ip.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        ip.parse::<std::net::Ipv4Addr>().is_ok()
    }
}

fn has_valid_ipv6() -> (bool, Option<String>) {
    match std::fs::read_to_string(IF_INET6_FILE_PATH) {
        Ok(content) => (has_global_ipv6_from_if_inet6(&content), None),
        Err(e) => (false, Some(format!("Error checking IPv6: {}", e))),
    }
}

fn has_global_ipv6_from_if_inet6(content: &str) -> bool {
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

fn parse_groups(file_path: &str) -> Result<HashMap<String, GroupData>, std::io::Error> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut data = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let mut parts = line.split(':');
        let (Some(name), Some(_), Some(gid)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let group_list = parts.next().map_or_else(Vec::new, |members| {
            members.split(',').map(String::from).collect::<Vec<_>>()
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

fn parse_users(file_path: &str) -> Result<HashMap<String, UserData>, std::io::Error> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
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

fn get_timezone() -> TimezoneData {
    if let Ok(tz) = env::var("TZ") {
        return TimezoneData { timezone: tz };
    }

    if let Ok(content) = std::fs::read_to_string(ETC_TIMEZONE_PATH) {
        if let Some(tz) = timezone_from_etc_timezone(&content) {
            return TimezoneData { timezone: tz };
        }
    }

    if let Ok(target) = std::fs::read_link(LOCALTIME_PATH) {
        if let Some(tz) = timezone_from_localtime_target(&target) {
            return TimezoneData { timezone: tz };
        }
    }

    TimezoneData {
        timezone: "Etc/UTC".to_string(),
    }
}

fn timezone_from_etc_timezone(content: &str) -> Option<String> {
    let tz = content.trim();
    if tz.is_empty() {
        None
    } else {
        Some(tz.to_string())
    }
}

fn timezone_from_localtime_target(target: &Path) -> Option<String> {
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

    #[test]
    fn sorts_json_keys_alphabetically_recursively() {
        let value = serde_json::json!({
            "z": 1,
            "a": {
                "d": 2,
                "b": 3
            },
            "m": [
                {
                    "k": 1,
                    "c": 2
                }
            ]
        });

        let sorted = sort_json_value(value);

        assert_eq!(
            serde_json::to_string(&sorted).unwrap(),
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
        let content = "\
not enough fields
1234
";
        assert!(!has_global_ipv6_from_if_inet6(content));
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
        let target = Path::new("/var/lib/custom/localtime");
        assert_eq!(timezone_from_localtime_target(target), None);
    }
}
