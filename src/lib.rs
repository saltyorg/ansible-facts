use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::TryStreamExt;
use reqwest::Client;
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::time::Duration;
use tokio::time::timeout;

pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_IP_RESPONSE_BYTES: u64 = 64;

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
    use std::io::Cursor;

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
