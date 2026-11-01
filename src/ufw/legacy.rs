//! Lists `filter` table chains from the legacy x_tables interface through the
//! same getsockopt calls iptables-legacy uses.

use super::Family;
use std::collections::BTreeSet;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::Path;

// linux/netfilter_ipv4/ip_tables.h and linux/netfilter_ipv6/ip6_tables.h.
const SO_GET_INFO: libc::c_int = 64;
const SO_GET_ENTRIES: libc::c_int = 65;
const TABLE_MAXNAMELEN: usize = 32;
// Offsets verified against the kernel headers with offsetof(). The layouts
// are identical on the 64-bit and 32-bit ARM targets because the trailing
// u64 counters are 8-byte aligned on every supported ABI.
const GETINFO_LEN: usize = 84;
const GETINFO_SIZE_OFFSET: usize = 80;
const GET_ENTRIES_TABLE_OFFSET: usize = 40;
const TARGET_NAME_OFFSET: usize = 2;
const TARGET_NAME_LEN: usize = 29;
const ERROR_NAME_OFFSET: usize = 32;
const ERROR_NAME_LEN: usize = 30;
const ERROR_TARGET: &str = "ERROR";
const MAX_TABLE_BYTES: usize = 64 * 1024 * 1024;
const ATTEMPTS: usize = 3;
const TABLE: &str = "filter";

#[derive(Clone, Copy)]
struct Layout {
    level: libc::c_int,
    domain: libc::c_int,
    /// Offset of `target_offset`; `next_offset` follows it.
    target_offset_field: usize,
}

impl Layout {
    fn for_family(family: Family) -> Self {
        match family {
            Family::Ipv4 => Self {
                level: libc::SOL_IP,
                domain: libc::AF_INET,
                target_offset_field: 88,
            },
            Family::Ipv6 => Self {
                level: libc::SOL_IPV6,
                domain: libc::AF_INET6,
                target_offset_field: 140,
            },
        }
    }
}

pub(super) fn filter_chains(
    family: Family,
    table_names: &Path,
) -> Result<BTreeSet<String>, String> {
    let label = family.label();
    // A table missing from this list is not loaded, so it holds no chains.
    // Querying it anyway would make the kernel autoload the table module. The
    // list itself is absent when the x_tables family module is not loaded.
    let names = match std::fs::read_to_string(table_names) {
        Ok(names) => names,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeSet::new()),
        Err(error) => return Err(format!("Failed to read {}: {error}", table_names.display())),
    };
    if !names.lines().any(|name| name.trim() == TABLE) {
        return Ok(BTreeSet::new());
    }
    let layout = Layout::for_family(family);
    let mut last_error = None;
    for _ in 0..ATTEMPTS {
        match read_entries(layout) {
            Ok(entries) => {
                return parse_chains(&entries, layout.target_offset_field)
                    .map_err(|error| format!("legacy iptables {label} ruleset: {error}"))
            }
            // EAGAIN: the table changed between the info and entries calls.
            Err(error) if error.raw_os_error() == Some(libc::EAGAIN) => last_error = Some(error),
            Err(error) => return Err(format!("legacy iptables {label} ruleset: {error}")),
        }
    }
    Err(format!(
        "legacy iptables {label} ruleset kept changing: {}",
        last_error
            .map(|error| error.to_string())
            .unwrap_or_default()
    ))
}

fn read_entries(layout: Layout) -> io::Result<Vec<u8>> {
    // SAFETY: plain socket creation; ownership is taken immediately.
    let fd = unsafe {
        libc::socket(
            layout.domain,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            libc::IPPROTO_RAW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };

    let mut info = [0_u8; GETINFO_LEN];
    info[..TABLE.len()].copy_from_slice(TABLE.as_bytes());
    get_option(&socket, layout, SO_GET_INFO, &mut info)?;
    let size = u32::from_ne_bytes(
        info[GETINFO_SIZE_OFFSET..GETINFO_SIZE_OFFSET + 4]
            .try_into()
            .unwrap(),
    ) as usize;
    if size > MAX_TABLE_BYTES {
        return Err(io::Error::other(format!(
            "table of {size} bytes is too large"
        )));
    }

    let mut request = vec![0_u8; GET_ENTRIES_TABLE_OFFSET + size];
    request[..TABLE.len()].copy_from_slice(TABLE.as_bytes());
    request[TABLE_MAXNAMELEN..TABLE_MAXNAMELEN + 4].copy_from_slice(&(size as u32).to_ne_bytes());
    get_option(&socket, layout, SO_GET_ENTRIES, &mut request)?;
    Ok(request.split_off(GET_ENTRIES_TABLE_OFFSET))
}

fn get_option(
    socket: &OwnedFd,
    layout: Layout,
    option: libc::c_int,
    buffer: &mut [u8],
) -> io::Result<()> {
    let mut length = buffer.len() as libc::socklen_t;
    // SAFETY: the buffer is valid for reads and writes of `length` bytes.
    let result = unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            layout.level,
            option,
            buffer.as_mut_ptr().cast(),
            &mut length,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// User-defined chains are introduced by an `ERROR` target entry whose data
/// is the chain name; the table ends with an `ERROR` entry named `ERROR`.
fn parse_chains(entries: &[u8], target_offset_field: usize) -> Result<BTreeSet<String>, String> {
    let mut chains = BTreeSet::new();
    let mut offset = 0;
    while offset < entries.len() {
        let entry = &entries[offset..];
        if entry.len() < target_offset_field + 4 {
            return Err("truncated rule entry".to_string());
        }
        let target_offset = read_u16(entry, target_offset_field) as usize;
        let next_offset = read_u16(entry, target_offset_field + 2) as usize;
        if next_offset == 0 || next_offset > entry.len() || target_offset >= next_offset {
            return Err("malformed rule entry offsets".to_string());
        }
        let target = &entry[target_offset..next_offset];
        if c_string(target, TARGET_NAME_OFFSET, TARGET_NAME_LEN).as_deref() == Some(ERROR_TARGET) {
            if let Some(name) = c_string(target, ERROR_NAME_OFFSET, ERROR_NAME_LEN) {
                if name != ERROR_TARGET {
                    chains.insert(name);
                }
            }
        }
        offset += next_offset;
    }
    Ok(chains)
}

fn c_string(data: &[u8], offset: usize, max_len: usize) -> Option<String> {
    let field = data.get(offset..)?;
    let field = &field[..field.len().min(max_len)];
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(field.len());
    Some(String::from_utf8_lossy(&field[..end]).into_owned())
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([data[offset], data[offset + 1]])
}

#[cfg(test)]
mod tests {
    use super::*;

    const IPV4_ENTRY_LEN: usize = 112;
    const IPV6_ENTRY_LEN: usize = 168;

    fn entry(entry_len: usize, field: usize, target: &str, data: &str) -> Vec<u8> {
        let target_len = ERROR_NAME_OFFSET + ERROR_NAME_LEN + 2;
        let mut bytes = vec![0_u8; entry_len + target_len];
        bytes[field..field + 2].copy_from_slice(&(entry_len as u16).to_ne_bytes());
        let next_offset = bytes.len() as u16;
        bytes[field + 2..field + 4].copy_from_slice(&next_offset.to_ne_bytes());
        let name = entry_len + TARGET_NAME_OFFSET;
        bytes[name..name + target.len()].copy_from_slice(target.as_bytes());
        let error = entry_len + ERROR_NAME_OFFSET;
        bytes[error..error + data.len()].copy_from_slice(data.as_bytes());
        bytes
    }

    fn table(entry_len: usize, field: usize) -> Vec<u8> {
        [
            entry(entry_len, field, "", ""),
            entry(entry_len, field, "ERROR", "ufw-user-input"),
            entry(entry_len, field, "ACCEPT", ""),
            entry(entry_len, field, "ERROR", "DOCKER"),
            entry(entry_len, field, "ERROR", "ERROR"),
        ]
        .concat()
    }

    #[test]
    fn parses_user_chains_for_both_families() {
        let expected: BTreeSet<String> = ["DOCKER", "ufw-user-input"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            parse_chains(&table(IPV4_ENTRY_LEN, 88), 88).unwrap(),
            expected
        );
        assert_eq!(
            parse_chains(&table(IPV6_ENTRY_LEN, 140), 140).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_malformed_offsets() {
        let mut bytes = entry(IPV4_ENTRY_LEN, 88, "ERROR", "x");
        bytes[90..92].copy_from_slice(&0_u16.to_ne_bytes());
        assert!(parse_chains(&bytes, 88).is_err());
        assert!(parse_chains(&bytes[..50], 88).is_err());
    }

    #[test]
    fn unloaded_filter_table_has_no_chains_without_querying() {
        let directory = tempfile::tempdir().unwrap();
        let names = directory.path().join("ip_tables_names");
        std::fs::write(&names, "nat\nmangle\n").unwrap();
        assert_eq!(
            filter_chains(Family::Ipv4, &names).unwrap(),
            BTreeSet::new()
        );
        std::fs::write(&names, "").unwrap();
        assert_eq!(
            filter_chains(Family::Ipv6, &names).unwrap(),
            BTreeSet::new()
        );
    }

    #[test]
    fn missing_table_list_means_no_tables_are_loaded() {
        let chains = filter_chains(Family::Ipv4, Path::new("/nonexistent/ip_tables_names"));
        assert_eq!(chains.unwrap(), BTreeSet::new());
    }

    #[test]
    fn unreadable_table_list_is_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let error = filter_chains(Family::Ipv4, directory.path());
        assert!(error.unwrap_err().contains("Failed to read"));
    }
}
