use reqwest::Client;
use saltbox_facts::{
    get_ip, get_timezone, has_valid_ipv6, ipv6_unavailable_error, parse_groups, parse_users,
    sort_json_value, IpOutput, Output,
};

const IPV4_URLS: [&str; 2] = ["https://ipify.saltbox.dev", "https://ipv4.icanhazip.com"];
const IPV6_URLS: [&str; 2] = ["https://ipify6.saltbox.dev", "https://ipv6.icanhazip.com"];
const GROUP_FILE_PATH: &str = "/etc/group";
const PASSWD_FILE_PATH: &str = "/etc/passwd";
const IF_INET6_FILE_PATH: &str = "/proc/net/if_inet6";
const ETC_TIMEZONE_PATH: &str = "/etc/timezone";
const LOCALTIME_PATH: &str = "/etc/localtime";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new();

    let groups_handle = tokio::task::spawn_blocking(|| parse_groups(GROUP_FILE_PATH));
    let users_handle = tokio::task::spawn_blocking(|| parse_users(PASSWD_FILE_PATH));
    let timezone_handle =
        tokio::task::spawn_blocking(|| get_timezone(ETC_TIMEZONE_PATH, LOCALTIME_PATH));

    let ip_future = async {
        let (ipv6_present, ipv6_check_error) = has_valid_ipv6(IF_INET6_FILE_PATH);
        let ((ipv4, ipv4_error), (ipv6, ipv6_error)) = if ipv6_present {
            tokio::join!(
                get_ip(&client, &IPV4_URLS, false),
                get_ip(&client, &IPV6_URLS, true)
            )
        } else {
            let error = ipv6_unavailable_error(ipv6_check_error.as_deref());
            (
                get_ip(&client, &IPV4_URLS, false).await,
                (None, Some(error)),
            )
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
        groups_result.map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })??;
    let users_data =
        users_result.map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })??;
    let timezone_data =
        timezone_result.map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })?;

    // Saltbox deliberately treats a missing public address as invalid, including
    // when no global IPv6 interface exists and the IPv6 request is skipped.
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
