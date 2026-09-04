use reqwest::Client;
use saltbox_facts::{
    get_timezone, has_valid_ipv6, ipv6_unavailable_error, parse_groups, parse_users,
    resolve_public_ips, sort_json_value, IpOutput, Output,
};
use std::ffi::OsStr;

const IPV4_URLS: [&str; 2] = ["https://ipify.saltbox.dev", "https://ipv4.icanhazip.com"];
const IPV6_URLS: [&str; 2] = ["https://ipify6.saltbox.dev", "https://ipv6.icanhazip.com"];
const GROUP_FILE_PATH: &str = "/etc/group";
const PASSWD_FILE_PATH: &str = "/etc/passwd";
const IF_INET6_FILE_PATH: &str = "/proc/net/if_inet6";
const ETC_TIMEZONE_PATH: &str = "/etc/timezone";
const LOCALTIME_PATH: &str = "/etc/localtime";
const VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecutionMode {
    Facts,
    Version,
}

fn execution_mode<I, S>(args: I) -> ExecutionMode
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut args = args.into_iter();
    match (args.next(), args.next()) {
        (Some(argument), None) if argument.as_ref() == OsStr::new("--version") => {
            ExecutionMode::Version
        }
        _ => ExecutionMode::Facts,
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    if execution_mode(std::env::args_os().skip(1)) == ExecutionMode::Version {
        println!("{VERSION}");
        return Ok(());
    }

    let client = Client::new();

    let groups_handle = tokio::task::spawn_blocking(|| parse_groups(GROUP_FILE_PATH));
    let users_handle = tokio::task::spawn_blocking(|| parse_users(PASSWD_FILE_PATH));
    let timezone_handle =
        tokio::task::spawn_blocking(|| get_timezone(ETC_TIMEZONE_PATH, LOCALTIME_PATH));

    let ip_future = async {
        let (ipv6_present, ipv6_probe_error) = has_valid_ipv6(IF_INET6_FILE_PATH);
        let unavailable_error = ipv6_unavailable_error(ipv6_probe_error.as_deref());
        resolve_public_ips(
            &client,
            &IPV4_URLS,
            &IPV6_URLS,
            ipv6_present,
            unavailable_error,
        )
        .await
    };

    let (resolution, groups_result, users_result, timezone_result) =
        tokio::join!(ip_future, groups_handle, users_handle, timezone_handle);

    let groups_data =
        groups_result.map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })??;
    let users_data =
        users_result.map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })??;
    let timezone_data =
        timezone_result.map_err(|error| -> Box<dyn std::error::Error> { Box::new(error) })?;

    // Saltbox deliberately treats a missing public address as invalid, including
    // when no global IPv6 interface exists and the IPv6 request is skipped.
    let failed_ipv4 = resolution.ipv4.address.is_none();
    let failed_ipv6 = resolution.ipv6.address.is_none();

    let result = Output {
        ip: IpOutput {
            cache_warning: resolution.cache_warning,
            public_ip: resolution.ipv4.address.unwrap_or_default(),
            public_ipv6: resolution.ipv6.address.unwrap_or_default(),
            error_ipv4: resolution.ipv4.error,
            error_ipv6: resolution.ipv6.error,
            failed_ipv4,
            failed_ipv6,
        },
        groups: groups_data,
        users: users_data,
        timezone: timezone_data,
    };

    let sorted_result = sort_json_value(serde_json::to_value(&result)?);
    println!("{}", serde_json::to_string(&sorted_result)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn execution_mode_selects_version_only_for_exact_version_argument() {
        let cases = [
            (Vec::<&str>::new(), ExecutionMode::Facts),
            (vec!["--version"], ExecutionMode::Version),
            (vec!["--version", "extra"], ExecutionMode::Facts),
            (vec!["--unknown"], ExecutionMode::Facts),
        ];

        for (args, expected) in cases {
            assert_eq!(execution_mode(args), expected);
        }
    }

    #[test]
    fn non_utf8_unknown_argument_selects_facts_mode() {
        let invalid_utf8 = OsString::from_vec(vec![0xff]);

        assert_eq!(execution_mode([invalid_utf8]), ExecutionMode::Facts);
    }
}
