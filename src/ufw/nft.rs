//! Lists `filter` table chains through an nf_tables netlink dump, the same
//! ruleset iptables-nft reads. Only `libc` is used, so static MUSL builds need
//! no C libraries.

use super::Family;
use std::collections::BTreeSet;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

// Linux UAPI values (linux/netlink.h, linux/netfilter/nfnetlink.h,
// linux/netfilter/nf_tables.h). These are stable kernel ABI.
const NETLINK_NETFILTER: libc::c_int = 12;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_MULTI: u16 = 0x2;
const NLM_F_DUMP: u16 = 0x300;
const NLM_F_DUMP_INTR: u16 = 0x10;
const NLMSG_ERROR: u16 = 0x2;
const NLMSG_DONE: u16 = 0x3;
const NLA_TYPE_MASK: u16 = !(0x8000 | 0x4000);
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFT_MSG_GETCHAIN: u16 = 4;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const NFNETLINK_V0: u8 = 0;

const NLMSG_HEADER_LEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
const RECEIVE_BUFFER_LEN: usize = 64 * 1024;
const RECEIVE_TIMEOUT: Duration = Duration::from_secs(2);
const DUMP_ATTEMPTS: usize = 3;
const TABLE: &str = "filter";

pub(super) fn filter_chains(family: Family) -> Result<BTreeSet<String>, String> {
    let label = family.label();
    for _ in 0..DUMP_ATTEMPTS {
        match dump_chains(family) {
            Ok(Dump::Complete(chains)) => return Ok(chains),
            Ok(Dump::Interrupted) => continue,
            Err(error) => return Err(format!("nftables {label} chain dump failed: {error}")),
        }
    }
    Err(format!(
        "nftables {label} chain dump was interrupted {DUMP_ATTEMPTS} times by ruleset changes"
    ))
}

#[derive(Debug, Eq, PartialEq)]
enum Dump {
    Complete(BTreeSet<String>),
    /// The ruleset changed during the dump; the result may be inconsistent.
    Interrupted,
}

fn dump_chains(family: Family) -> io::Result<Dump> {
    let socket = open_socket()?;
    let sequence = 1;
    let request = getchain_request(family, sequence);
    // SAFETY: the buffer is valid for its length and the descriptor is owned.
    let sent = unsafe {
        libc::send(
            socket.as_raw_fd(),
            request.as_ptr().cast(),
            request.len(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    let mut parser = DumpParser::new(sequence);
    let mut buffer = vec![0_u8; RECEIVE_BUFFER_LEN];
    loop {
        // SAFETY: the buffer is valid for writes of its length. MSG_TRUNC makes
        // the kernel report the full datagram length so truncation is detected.
        let received = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_TRUNC,
            )
        };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received = received as usize;
        if received > buffer.len() {
            return Err(io::Error::other(format!(
                "netlink message of {received} bytes exceeded the receive buffer"
            )));
        }
        if received == 0 {
            return Err(io::Error::other("netlink socket closed during dump"));
        }
        if let Some(dump) = parser.feed(&buffer[..received])? {
            return Ok(dump);
        }
    }
}

fn open_socket() -> io::Result<OwnedFd> {
    // SAFETY: plain socket creation; ownership of a valid descriptor is taken
    // immediately so it is closed on every path.
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_NETFILTER,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let timeout = libc::timeval {
        tv_sec: RECEIVE_TIMEOUT.as_secs() as _,
        tv_usec: 0,
    };
    // SAFETY: `timeout` is a valid timeval for the duration of the call.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(socket)
}

fn getchain_request(family: Family, sequence: u32) -> Vec<u8> {
    let length = (NLMSG_HEADER_LEN + NFGENMSG_LEN) as u32;
    let message_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETCHAIN;
    let mut request = Vec::with_capacity(length as usize);
    request.extend_from_slice(&length.to_ne_bytes());
    request.extend_from_slice(&message_type.to_ne_bytes());
    request.extend_from_slice(&(NLM_F_REQUEST | NLM_F_DUMP).to_ne_bytes());
    request.extend_from_slice(&sequence.to_ne_bytes());
    request.extend_from_slice(&0_u32.to_ne_bytes());
    request.push(match family {
        Family::Ipv4 => NFPROTO_IPV4,
        Family::Ipv6 => NFPROTO_IPV6,
    });
    request.push(NFNETLINK_V0);
    request.extend_from_slice(&0_u16.to_be_bytes());
    request
}

struct DumpParser {
    sequence: u32,
    chains: BTreeSet<String>,
    interrupted: bool,
}

impl DumpParser {
    fn new(sequence: u32) -> Self {
        Self {
            sequence,
            chains: BTreeSet::new(),
            interrupted: false,
        }
    }

    /// Consumes one received datagram; returns the result once the dump ends.
    fn feed(&mut self, mut data: &[u8]) -> io::Result<Option<Dump>> {
        while data.len() >= NLMSG_HEADER_LEN {
            let length = read_u32(data, 0) as usize;
            let message_type = read_u16(data, 4);
            let flags = read_u16(data, 6);
            let sequence = read_u32(data, 8);
            if length < NLMSG_HEADER_LEN || length > data.len() {
                return Err(io::Error::other("malformed netlink message length"));
            }
            let message = &data[..length];
            data = &data[align(length).min(data.len())..];
            if sequence != self.sequence {
                continue;
            }
            if flags & NLM_F_DUMP_INTR != 0 {
                self.interrupted = true;
            }
            match message_type {
                NLMSG_DONE => return Ok(Some(self.finish())),
                NLMSG_ERROR => {
                    if message.len() < NLMSG_HEADER_LEN + 4 {
                        return Err(io::Error::other("truncated netlink error message"));
                    }
                    let code = i32::from_ne_bytes(
                        message[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + 4]
                            .try_into()
                            .unwrap(),
                    );
                    if code == 0 {
                        // An acknowledgement; dumps end with NLMSG_DONE.
                        continue;
                    }
                    return Err(io::Error::from_raw_os_error(-code));
                }
                _ => {
                    if let Some(name) = filter_chain_name(message) {
                        self.chains.insert(name);
                    }
                    if flags & NLM_F_MULTI == 0 {
                        return Ok(Some(self.finish()));
                    }
                }
            }
        }
        Ok(None)
    }

    fn finish(&mut self) -> Dump {
        if self.interrupted {
            Dump::Interrupted
        } else {
            Dump::Complete(std::mem::take(&mut self.chains))
        }
    }
}

/// The chain name of a NEWCHAIN message whose table is `filter`.
fn filter_chain_name(message: &[u8]) -> Option<String> {
    let mut attributes = message.get(NLMSG_HEADER_LEN + NFGENMSG_LEN..)?;
    let mut table = None;
    let mut name = None;
    while attributes.len() >= 4 {
        let length = read_u16(attributes, 0) as usize;
        let attribute_type = read_u16(attributes, 2) & NLA_TYPE_MASK;
        if length < 4 || length > attributes.len() {
            break;
        }
        let payload = &attributes[4..length];
        match attribute_type {
            NFTA_CHAIN_TABLE => table = Some(nul_terminated(payload)),
            NFTA_CHAIN_NAME => name = Some(nul_terminated(payload)),
            _ => {}
        }
        attributes = &attributes[align(length).min(attributes.len())..];
    }
    (table.as_deref() == Some(TABLE)).then_some(name).flatten()
}

fn nul_terminated(bytes: &[u8]) -> String {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn align(length: usize) -> usize {
    (length + 3) & !3
}

fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_ne_bytes([data[offset], data[offset + 1]])
}

fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_ne_bytes(data[offset..offset + 4].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attribute(attribute_type: u16, value: &str) -> Vec<u8> {
        let mut payload = value.as_bytes().to_vec();
        payload.push(0);
        let length = (4 + payload.len()) as u16;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&length.to_ne_bytes());
        bytes.extend_from_slice(&attribute_type.to_ne_bytes());
        bytes.extend_from_slice(&payload);
        bytes.resize(align(bytes.len()), 0);
        bytes
    }

    fn message(message_type: u16, flags: u16, sequence: u32, body: &[u8]) -> Vec<u8> {
        let length = (NLMSG_HEADER_LEN + body.len()) as u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&length.to_ne_bytes());
        bytes.extend_from_slice(&message_type.to_ne_bytes());
        bytes.extend_from_slice(&flags.to_ne_bytes());
        bytes.extend_from_slice(&sequence.to_ne_bytes());
        bytes.extend_from_slice(&0_u32.to_ne_bytes());
        bytes.extend_from_slice(body);
        bytes.resize(align(bytes.len()), 0);
        bytes
    }

    fn chain(table: &str, name: &str, flags: u16) -> Vec<u8> {
        let mut body = vec![NFPROTO_IPV4, NFNETLINK_V0, 0, 0];
        body.extend(attribute(NFTA_CHAIN_TABLE, table));
        body.extend(attribute(NFTA_CHAIN_NAME, name));
        message((NFNL_SUBSYS_NFTABLES << 8) | 3, flags, 1, &body)
    }

    fn done(flags: u16) -> Vec<u8> {
        message(NLMSG_DONE, flags, 1, &0_i32.to_ne_bytes())
    }

    #[test]
    fn builds_a_getchain_dump_request() {
        let request = getchain_request(Family::Ipv6, 7);
        assert_eq!(request.len(), 20);
        assert_eq!(read_u32(&request, 0), 20);
        assert_eq!(read_u16(&request, 4), 0x0a04);
        assert_eq!(read_u16(&request, 6), NLM_F_REQUEST | NLM_F_DUMP);
        assert_eq!(read_u32(&request, 8), 7);
        assert_eq!(request[16], NFPROTO_IPV6);
    }

    #[test]
    fn collects_filter_chains_across_datagrams() {
        let mut parser = DumpParser::new(1);
        let mut first = chain("filter", "ufw-user-input", NLM_F_MULTI);
        first.extend(chain("nat", "ufw-user-output", NLM_F_MULTI));
        assert_eq!(parser.feed(&first).unwrap(), None);
        let mut second = chain("filter", "DOCKER", NLM_F_MULTI);
        second.extend(done(NLM_F_MULTI));
        let expected: BTreeSet<String> = ["DOCKER", "ufw-user-input"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(
            parser.feed(&second).unwrap(),
            Some(Dump::Complete(expected))
        );
    }

    #[test]
    fn reports_interrupted_dumps() {
        let mut parser = DumpParser::new(1);
        let mut data = chain("filter", "INPUT", NLM_F_MULTI | NLM_F_DUMP_INTR);
        data.extend(done(NLM_F_MULTI));
        assert_eq!(parser.feed(&data).unwrap(), Some(Dump::Interrupted));
    }

    #[test]
    fn surfaces_kernel_errors() {
        let mut parser = DumpParser::new(1);
        let error = message(NLMSG_ERROR, 0, 1, &(-libc::EPERM).to_ne_bytes());
        let error = parser.feed(&error).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EPERM));
    }

    #[test]
    fn ignores_other_sequences_and_rejects_bad_lengths() {
        let mut parser = DumpParser::new(1);
        let foreign = message(NLMSG_DONE, 0, 9, &[0; 4]);
        assert_eq!(parser.feed(&foreign).unwrap(), None);

        let mut malformed = done(0);
        malformed[0..4].copy_from_slice(&1000_u32.to_ne_bytes());
        assert!(parser.feed(&malformed).is_err());
    }

    #[test]
    fn empty_dump_has_no_chains() {
        let mut parser = DumpParser::new(1);
        assert_eq!(
            parser.feed(&done(NLM_F_MULTI)).unwrap(),
            Some(Dump::Complete(BTreeSet::new()))
        );
    }
}
