# saltbox-facts

`saltbox-facts` is the executable Ansible local fact used by Saltbox. It emits
one compact JSON object containing the host's public addresses, local users and
groups, and timezone.

The binary targets Linux and requires Rust 1.89 or newer when built from
source. Tagged releases publish static MUSL binaries for amd64, arm64, ARMv7,
ARMv6 hard-float, and ARMv5TE soft-float. The unqualified `saltbox-facts`
release asset is the legacy amd64 name used by the standard Saltbox installer.
The release job executes the ARMv5TE binary under an emulated ARM926 CPU before
publishing it.

## Output contract

Running the binary without arguments prints one JSON object to standard output:

```json
{
  "groups": {},
  "ip": {
    "cache_warning": null,
    "error_ipv4": null,
    "error_ipv6": null,
    "failed_ipv4": false,
    "failed_ipv6": false,
    "public_ip": "1.1.1.1",
    "public_ipv6": "2606:4700:4700::1111"
  },
  "timezone": {
    "timezone": "Europe/Copenhagen"
  },
  "users": {}
}
```

Object keys are emitted in deterministic alphabetical order. A public-address
failure is represented inside the JSON rather than as a process failure:
`failed_ipv4` or `failed_ipv6` is `true`, the corresponding address is empty,
and the error field explains the failed attempts. Failures reading mandatory
local account files still make the process fail. Nonfatal cache problems are
reported in `cache_warning`; the field is always present and is `null` when no
warning occurred.

`saltbox-facts --version` prints only the compiled semantic version and exits
before filesystem, cache, or network work. Unknown or additional arguments
retain the executable-local-fact behavior for compatibility.

## Public-address resolution

IPv4 and IPv6 are resolved independently from these provider pairs:
`https://ipify.saltbox.dev` and `https://ipv4.icanhazip.com` for IPv4, and
`https://ipify6.saltbox.dev` and `https://ipv6.icanhazip.com` for IPv6. Each
round queries both configured sources concurrently and accepts the first
successful response. Source ordering does not determine which successful
response wins, but all-failure diagnostics are rendered in configured source
order.

The first-party endpoint returns the source address observed by Traefik, while
icanhazip observes the source address of its connection. Either can therefore
report the address after NAT or through a proxy, depending on the network path.
Responses are accepted when they are valid syntax for the requested IP family
and are returned in canonical form. Providers are availability sources rather
than an address-consensus system: the local `/proc/net/if_inet6` check only
gates whether IPv6 attempts are made. No LAN or IANA denylist is applied,
because an echo service's observation—not registry classification—is the
boundary this fact needs to report.

A failed round is retried twice, for at most three complete rounds. Requests
have a three-second timeout, with 250 ms and 750 ms delays before the second and
third rounds. When no local global-scope IPv6 interface is present, IPv6 HTTP
requests are skipped.

## Cache contract

Successful addresses are cached independently for 15 minutes at:

```text
/var/cache/saltbox/facts/public-ip.json
```

The cache is accepted only when its namespace, private facts directory, and
file are owned by the process's effective user and have trusted permissions.
The namespace must not be group- or other-writable; the facts directory and
cache file must expose no group or other permissions. Writes reconcile the
facts directory, cache file, and lock file to `0700`, `0600`, and `0600`.

Reads are size-bounded and reject symlinks, FIFOs, non-regular files, malformed
JSON, unsupported schemas, future timestamps, expired entries, and addresses
from the wrong family. Writers take a bounded advisory lock, reload and merge
under that lock, atomically rename a same-directory temporary file, and sync
the file and directory. Cache failures remain soft: a live lookup result is
still returned, but an untrusted cache is never used. Missing and expired
entries are normal cache misses and do not produce warnings. Invalid or unsafe
reads use the `cache read ignored: ` prefix; lock, directory, write, rename,
sync, and blocking-task failures during persistence use `cache write skipped: `.
When both phases warn, the read warning appears first and the phases are joined
with ` | `. Valid IPv4 and IPv6 entries remain independent when only the other
family's entry is invalid.

## Development

Run the same native checks used by CI:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo test --all-targets --all-features --locked
cargo build --release --locked
```

The release workflow performs the MUSL cross-builds. Its
`AWS_LC_SYS_NO_JITTER_ENTROPY=1` setting is deliberately scoped to those cross
builds; native developer and CI builds retain AWS-LC's default entropy-source
configuration.
