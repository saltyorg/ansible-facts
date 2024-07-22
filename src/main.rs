use std::fs::File;
use std::io::{BufRead, BufReader};
use std::process::Command;
use std::time::Duration;
use tokio::time::timeout;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::env;

const TIMEOUT: u64 = 3;
const GROUP_FILE_PATH: &str = "/etc/group";
const PASSWD_FILE_PATH: &str = "/etc/passwd";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    let ipv4_urls = vec![
        "https://ipify.saltbox.dev",
        "https://ipv4.icanhazip.com",
    ];
    let ipv6_urls = vec![
        "https://ipify6.saltbox.dev",
        "https://ipv6.icanhazip.com",
    ];

    let (ipv4, ipv4_error) = get_ip(&client, &ipv4_urls, false).await;
    let (ipv6_present, ipv6_check_error) = has_valid_ipv6();

    let (ipv6, ipv6_error) = if ipv6_present {
        get_ip(&client, &ipv6_urls, true).await
    } else {
        (None, None)
    };

    let groups_data = parse_file(GROUP_FILE_PATH, 3)?;
    let users_data = parse_file(PASSWD_FILE_PATH, 7)?;
    let timezone_data = get_timezone()?;

    let result = json!({
        "ip": {
            "public_ip": ipv4.as_deref().unwrap_or(""),
            "public_ipv6": ipv6.as_deref().unwrap_or(""),
            "error_ipv4": ipv4_error,
            "error_ipv6": ipv6_error,
            "failed_ipv4": ipv4.is_none(),
            "failed_ipv6": ipv6.is_none(),
            "ipv6_check_error": ipv6_check_error
        },
        "groups": groups_data,
        "users": users_data,
        "timezone": timezone_data
    });

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

async fn get_ip(client: &Client, urls: &[&str], is_ipv6: bool) -> (Option<String>, Option<String>) {
    for url in urls {
        match timeout(Duration::from_secs(TIMEOUT), client.get(*url).send()).await {
            Ok(Ok(response)) => {
                if response.status().is_success() {
                    if let Ok(ip) = response.text().await {
                        let ip = ip.trim();
                        if validate_ip(ip, is_ipv6) {
                            return (Some(ip.to_string()), None);
                        } else {
                            return (None, Some(format!("Invalid {} address received.", if is_ipv6 { "IPv6" } else { "IPv4" })));
                        }
                    }
                } else {
                    return (None, Some(format!("HTTP {} received from {}.", response.status(), url)));
                }
            }
            _ => continue,
        }
    }
    (None, Some("All requests failed".to_string()))
}

fn validate_ip(ip: &str, is_ipv6: bool) -> bool {
    if is_ipv6 {
        ip.parse::<std::net::Ipv6Addr>().is_ok()
    } else {
        ip.parse::<std::net::Ipv4Addr>().is_ok()
    }
}

fn has_valid_ipv6() -> (bool, Option<String>) {
    match Command::new("ip").args(&["-6", "addr", "show", "scope", "global"]).output() {
        Ok(output) => (!output.stdout.is_empty(), None),
        Err(e) => (false, Some(format!("Error checking IPv6: {}", e))),
    }
}

fn parse_file(file_path: &str, min_tokens: usize) -> Result<Value, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut data = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let tokens: Vec<&str> = line.split(':').collect();
        if tokens.len() >= min_tokens {
            let value = if file_path == GROUP_FILE_PATH {
                json!({
                    "gid": tokens[2],
                    "group-list": tokens.get(3).map_or(Vec::new(), |&s| s.split(',').map(String::from).collect::<Vec<_>>())
                })
            } else {
                json!({
                    "uid": tokens[2],
                    "gid": tokens[3],
                    "comment": tokens[4],
                    "home": tokens[5],
                    "shell": tokens[6],
                })
            };
            data.insert(tokens[0].to_string(), value);
        }
    }

    Ok(json!(data))
}

fn get_timezone() -> Result<Value, Box<dyn std::error::Error>> {
    if let Ok(tz) = env::var("TZ") {
        return Ok(json!({ "timezone": tz }));
    }

    let output = Command::new("sh")
        .arg("-c")
        .arg("cat /etc/timezone 2>/dev/null || ls -l /etc/localtime | sed 's/.* -> //' | sed 's/^.*zoneinfo\\///'")
        .output()?;

    if output.status.success() {
        let tz = String::from_utf8(output.stdout)?.trim().to_string();
        if !tz.is_empty() {
            return Ok(json!({ "timezone": tz }));
        }
    }

    Ok(json!({ "timezone": "Etc/UTC" }))
}
