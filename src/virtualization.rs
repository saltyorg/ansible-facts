//! Virtualization detection delegated to `systemd-detect-virt`.
//!
//! Saltbox supports only systemd-based Ubuntu releases, where the tool is
//! always present and is the reference implementation. Running it from here
//! keeps exact output parity while overlapping with the other fact work.

use serde::Serialize;
use std::process::Stdio;
use std::time::Duration;
use tokio::process::Command;

pub const SYSTEMD_DETECT_VIRT_PATH: &str = "/usr/bin/systemd-detect-virt";
pub const DETECT_TIMEOUT: Duration = Duration::from_secs(2);

/// Container identifiers printed by systemd-detect-virt. Any other value
/// except `none` is a virtual machine.
const CONTAINER_TYPES: [&str; 11] = [
    "container-other",
    "docker",
    "lxc",
    "lxc-libvirt",
    "openvz",
    "podman",
    "pouch",
    "proot",
    "rkt",
    "systemd-nspawn",
    "wsl",
];

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct VirtualizationData {
    pub error: Option<String>,
    /// `vm`, `container`, or `none`; `null` when detection failed.
    pub kind: Option<&'static str>,
    /// The exact systemd-detect-virt identifier, e.g. `kvm` or `none`.
    #[serde(rename = "type")]
    pub virt_type: Option<String>,
}

/// Runs `command` (program followed by arguments) and interprets its output
/// like systemd-detect-virt.
pub async fn detect_virtualization(command: &[&str], timeout: Duration) -> VirtualizationData {
    let Some((&program, arguments)) = command.split_first() else {
        return failure("No virtualization detection command was configured".to_string());
    };
    let child = Command::new(program)
        .args(arguments)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn();
    let child = match child {
        Ok(child) => child,
        Err(error) => return failure(format!("Failed to run {program}: {error}")),
    };

    let output = match tokio::time::timeout(timeout, child.wait_with_output()).await {
        Ok(Ok(output)) => output,
        Ok(Err(error)) => return failure(format!("Failed to run {program}: {error}")),
        // Dropping the future drops the child, and kill_on_drop terminates it.
        Err(_) => return failure(format!("{program} timed out after {timeout:?}")),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let identifier = stdout.trim();
    // Exit status 1 with `none` is the normal bare-metal result.
    let recognised = match output.status.code() {
        Some(0) => !identifier.is_empty() && identifier != "none",
        Some(1) => identifier == "none",
        _ => false,
    };
    if !recognised {
        return failure(format!(
            "{program} exited with {} and printed '{identifier}'",
            output.status
        ));
    }

    VirtualizationData {
        error: None,
        kind: Some(classify(identifier)),
        virt_type: Some(identifier.to_string()),
    }
}

fn failure(error: String) -> VirtualizationData {
    VirtualizationData {
        error: Some(error),
        kind: None,
        virt_type: None,
    }
}

pub fn classify(identifier: &str) -> &'static str {
    if identifier == "none" {
        "none"
    } else if CONTAINER_TYPES.contains(&identifier) {
        "container"
    } else {
        "vm"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // An inline shell avoids writing executables, which can fail with
    // ETXTBSY while parallel tests fork.
    async fn run(body: &str, timeout: Duration) -> VirtualizationData {
        detect_virtualization(&["/bin/sh", "-c", body], timeout).await
    }

    #[test]
    fn classifies_identifiers() {
        assert_eq!(classify("none"), "none");
        assert_eq!(classify("kvm"), "vm");
        assert_eq!(classify("microsoft"), "vm");
        assert_eq!(classify("lxc"), "container");
        assert_eq!(classify("wsl"), "container");
    }

    #[tokio::test]
    async fn reports_a_virtual_machine() {
        let data = run("echo kvm", DETECT_TIMEOUT).await;
        assert_eq!(
            data,
            VirtualizationData {
                error: None,
                kind: Some("vm"),
                virt_type: Some("kvm".to_string()),
            }
        );
    }

    #[tokio::test]
    async fn reports_bare_metal_from_exit_status_one() {
        let data = run("echo none; exit 1", DETECT_TIMEOUT).await;
        assert_eq!(data.kind, Some("none"));
        assert_eq!(data.virt_type.as_deref(), Some("none"));
        assert_eq!(data.error, None);
    }

    #[tokio::test]
    async fn rejects_unexpected_output() {
        let data = run("exit 3", DETECT_TIMEOUT).await;
        assert_eq!(data.virt_type, None);
        assert!(data.error.unwrap().contains("exited with"));
    }

    #[tokio::test]
    async fn reports_a_missing_program() {
        let data =
            detect_virtualization(&["/nonexistent/systemd-detect-virt"], DETECT_TIMEOUT).await;
        assert_eq!(data.kind, None);
        assert!(data.error.unwrap().starts_with("Failed to run"));
    }

    #[tokio::test]
    async fn rejects_an_empty_command() {
        let data = detect_virtualization(&[], DETECT_TIMEOUT).await;
        assert!(data.error.is_some());
    }

    #[tokio::test]
    async fn times_out_a_hung_program() {
        let data = run("exec sleep 30", Duration::from_millis(100)).await;
        assert!(data.error.unwrap().contains("timed out"));
    }
}
