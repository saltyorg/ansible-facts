# Stack Context

Generated: 2026-10-26

## Stack
- **Language**: Rust 2021 edition; MSRV is `package.rust-version` in Cargo.toml; Linux/Unix-specific host integration
- **Framework**: No web framework; Tokio current-thread async runtime and Reqwest HTTP client
- **Data**: Serde and serde_json for the executable Ansible-fact JSON contract
- **Build**: Cargo with a committed lockfile; native release builds and static MUSL cross-builds
- **Test**: Built-in Rust test harness via `cargo test --all-targets --all-features --locked`
- **Benchmark**: Criterion benchmark in `benches/local_paths.rs` (compiled and smoke-run by all-target tests)
- **Lint**: Clippy with warnings denied (CI gate: yes)
- **Format**: rustfmt (CI gate: yes)

## Secondary Languages
- YAML (GitHub Actions CI and release automation)
- Shell (embedded in workflow steps for release validation and packaging)
- JSON (Renovate dependency-update policy; routine updates automerge after checks pass)
- TOML (`deny.toml` cargo-deny supply-chain policy)

## Conventions
- Error handling: `io::Result` for required reads; named lookup outcomes; cache failures stay soft and surface through `ip.cache_warning`
- Module structure: `main.rs` emits facts; `lib.rs` owns output/local parsing; `public_ip/` separates address, HTTP, cache, and resolver concerns
- Naming: idiomatic Rust `snake_case` functions/modules and `PascalCase` types; Serde preserves external JSON field names
- Tests: inline unit tests, real local-TCP fixtures, `tests/cli.rs` binary coverage, and one Criterion benchmark

## CI Gates
- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features --locked -- -D warnings`
- `cargo test --all-targets --all-features --locked`
- `cargo test --release --all-targets --all-features --locked` and release build
- MSRV toolchain (read from Cargo.toml) locked all-target tests and release build
- `cargo deny --locked check`: RustSec advisories, yanked/unsound crates, licenses, bans, sources
- Actionlint with ShellCheck and zizmor (`.github/zizmor.yml`); tool versions are Renovate-annotated in `ci.yml`

## Release Gates
- Validate tag-derived SemVer and synchronize `Cargo.toml`/`Cargo.lock`
- Require reusable CI, cross-build five static MUSL targets, and smoke-test ARMv5 under QEMU before publication
