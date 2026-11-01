# saltbox-facts

`saltbox-facts` is the executable Ansible local fact used by Saltbox. It emits
one compact JSON object containing the host's public addresses, local users and
groups, timezone, Saltbox repository status, CPU level, UFW state, and
virtualization type.

The binary targets Linux. Source builds require current stable Rust, with the
required version declared by `package.rust-version` in [Cargo.toml](Cargo.toml).
Renovate maintains that requirement, and CI reads it directly from the manifest.
Tagged releases publish static MUSL binaries for amd64, arm64, ARMv7,
ARMv6 hard-float, and ARMv5TE soft-float. The unqualified `saltbox-facts`
release asset is the legacy amd64 name used by the standard Saltbox installer.
The release job executes the ARMv5TE binary under an emulated ARM926 CPU before
publishing it.

## Output contract

Running the binary without arguments prints one JSON object to standard output:

```json
{
  "cpu": {
    "arch": "x86_64",
    "error": null,
    "flags_missing_for_next_level": ["avx512bw", "avx512cd", "avx512dq", "avx512f", "avx512vl"],
    "x86_64_level": 3
  },
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
  "repo": {
    "ahead_by": 0,
    "behind_by": 0,
    "branch": "master",
    "commit": "40389b0583b4a484de2c8e061afa4ae75c6e60c6",
    "detached": false,
    "error": null,
    "official": true,
    "path": "/srv/git/saltbox",
    "remote_url": "https://github.com/saltyorg/saltbox.git",
    "source": "svm",
    "status": "identical",
    "upstream_commit": "40389b0583b4a484de2c8e061afa4ae75c6e60c6"
  },
  "timezone": {
    "timezone": "Europe/Copenhagen"
  },
  "ufw": {
    "active": false,
    "backend": "nftables",
    "error": null,
    "installed": true
  },
  "users": {},
  "virtualization": {
    "error": null,
    "kind": "vm",
    "type": "kvm"
  }
}
```

Object keys are emitted in deterministic alphabetical order. A public-address
failure is represented inside the JSON rather than as a process failure:
`failed_ipv4` or `failed_ipv6` is `true`, the corresponding address is empty,
and the error field explains the failed attempts. Failures reading mandatory
local account files still make the process fail. Nonfatal cache problems are
reported in `cache_warning`; the field is always present and is `null` when no
warning occurred. The `cpu`, `repo`, `ufw`, and `virtualization` sections are
likewise never process failures: each always emits every field and explains
problems in its `error` field.

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

## Repository status

The `repo` section describes the Saltbox checkout containing the fact's
`ansible_facts.d` directory, falling back to `/srv/git/saltbox`. Git metadata
(`HEAD`, loose and packed refs, worktree `gitdir`/`commondir` files, and the
origin URL in `config`) is read directly rather than by running `git`, so the
result does not depend on `safe.directory` or repository ownership. Only the
files ref storage is supported; reftable repositories report an error.

`official` is `true` only when origin is the public
`https://github.com/saltyorg/Saltbox` URL, ignoring case, a trailing slash, and
`.git`. Every other remote, including forks, SSH remotes, and missing remotes,
reports `status: "unsupported"` and makes no network request. Credentials
embedded in the URL are removed from `remote_url`.

For official checkouts the commit is compared with the same branch of
`saltyorg/Saltbox` (`master` when HEAD is detached) using the GitHub compare
API. Each request goes to the svm proxy first and directly to
`api.github.com` only when svm fails or returns an empty response; requests
time out after three seconds and results are never cached locally. `status` is
one of:

| Status | Meaning |
|---|---|
| `identical` | The commit is the upstream branch head. |
| `behind`, `ahead`, `diverged` | GitHub's comparison; see `ahead_by` and `behind_by`. |
| `local_only` | The branch exists upstream but GitHub does not know the commit. |
| `branch_not_upstream` | The branch does not exist in `saltyorg/Saltbox`. |
| `unsupported` | Origin is not the official repository. |
| `unknown` | Local metadata or the API could not be read; see `error`. |

`source` names the endpoint (`svm` or `github`) that produced the result.

## CPU level

`x86_64_level` is the highest x86-64 psABI microarchitecture level (1–4) whose
features are all present, checking levels cumulatively against the flags shared
by every processor in `/proc/cpuinfo`. Level 0 means even the baseline is
incomplete. `flags_missing_for_next_level` lists the `/proc/cpuinfo` flag names
blocking the next level and is empty at level 4. `arch` is the kernel
architecture from `/proc/sys/kernel/arch`, falling back to `uname`; on other
architectures the level and missing-flag list are `null`.

## UFW state

`active` mirrors `ufw status` without running `ufw` or `iptables`. ufw reports
itself active when the `ufw-user-input`, `ufw-user-output`, and
`ufw-user-forward` chains exist in the `filter` table, plus the `ufw6-user-*`
chains when `IPV6=yes` in `/etc/default/ufw` and the kernel has IPv6. The fact
follows `/usr/sbin/iptables` to the backend ufw uses and reads the chains from
the kernel: an nf_tables netlink dump for `nftables`, or the x_tables
`getsockopt` interface for `legacy`. Legacy tables absent from
`/proc/net/ip{,6}_tables_names` are treated as empty, so querying never loads
table modules.

`installed` is `false` and `active` is `false` when `/usr/sbin/ufw` is absent.
`active` is `null` when the ruleset cannot be read, such as in a container
without `CAP_NET_ADMIN`. When the IPv4 chains are loaded but the required IPv6
chains are not, `active` is `true` and `error` describes the IPv6 problem,
because the IPv4 firewall is enforcing although `ufw status` itself errors.

## Virtualization

`type` is the exact output of `/usr/bin/systemd-detect-virt` (for example
`kvm`, `lxc`, or `none`), which runs concurrently with the other lookups under
a two-second timeout. `kind` classifies it as `vm`, `container`, or `none`.
Both are `null`, with `error` set, when the command is missing, fails, or times
out.

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
