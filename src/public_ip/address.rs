use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AddressFamily {
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "IPv4",
            Self::Ipv6 => "IPv6",
        }
    }
}

pub(super) fn canonical_public_ip(ip: &str, family: AddressFamily) -> Option<String> {
    // Echo services report what a request looks like at their boundary; they
    // are availability sources, not a consensus system. Trust syntax and the
    // requested family instead of trying to maintain a LAN/IANA denylist.
    let ip = ip.trim();
    match family {
        AddressFamily::Ipv4 => ip
            .parse::<Ipv4Addr>()
            .ok()
            .map(|address| address.to_string()),
        AddressFamily::Ipv6 => ip
            .parse::<Ipv6Addr>()
            .ok()
            .map(|address| address.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalizes_addresses_for_the_requested_family() {
        assert_eq!(
            canonical_public_ip(" 8.8.8.8\n", AddressFamily::Ipv4),
            Some("8.8.8.8".to_string())
        );
        assert_eq!(
            canonical_public_ip(
                "2606:4700:4700:0000:0000:0000:0000:1111",
                AddressFamily::Ipv6
            ),
            Some("2606:4700:4700::1111".to_string())
        );
        assert_eq!(canonical_public_ip("::1", AddressFamily::Ipv4), None);
        assert_eq!(canonical_public_ip("10.0.0.1", AddressFamily::Ipv6), None);
    }
}
