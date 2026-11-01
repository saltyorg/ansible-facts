//! CPU architecture and x86-64 microarchitecture level detection.
//!
//! Levels follow the x86-64 psABI definitions (x86-64-v1 through v4) using the
//! flag names Linux prints in `/proc/cpuinfo`. The kernel already removes flags
//! whose register state it has not enabled (for example AVX without XSAVE
//! support), so the printed flags reflect what processes can actually use.

use serde::Serialize;
use std::collections::BTreeSet;

/// Required `/proc/cpuinfo` flags per level. Each level also requires every
/// level before it. Linux reports SSE3 as `pni` and LZCNT as `abm`, and prints
/// no `osxsave` flag, so `xsave` stands in for the OS-support requirement.
const X86_64_LEVELS: [&[&str]; 4] = [
    &[
        "cmov", "cx8", "fpu", "fxsr", "lm", "mmx", "sse", "sse2", "syscall",
    ],
    &[
        "cx16", "lahf_lm", "pni", "popcnt", "sse4_1", "sse4_2", "ssse3",
    ],
    &[
        "abm", "avx", "avx2", "bmi1", "bmi2", "f16c", "fma", "movbe", "xsave",
    ],
    &["avx512bw", "avx512cd", "avx512dq", "avx512f", "avx512vl"],
];

#[derive(Debug, Eq, PartialEq, Serialize)]
pub struct CpuData {
    /// Kernel machine architecture, e.g. `x86_64` or `aarch64`.
    pub arch: Option<String>,
    pub error: Option<String>,
    /// Flags preventing the next level; empty at the highest level, `null`
    /// when no x86-64 level applies.
    pub flags_missing_for_next_level: Option<Vec<String>>,
    /// Highest fully supported x86-64 level (0 when even the baseline is
    /// incomplete); `null` on other architectures or when flags are unknown.
    pub x86_64_level: Option<u8>,
}

pub fn get_cpu(cpuinfo_path: &str, kernel_arch_path: &str) -> CpuData {
    let arch = kernel_arch(kernel_arch_path);
    match std::fs::read_to_string(cpuinfo_path) {
        Ok(content) => cpu_from_cpuinfo(arch, &content),
        Err(error) => CpuData {
            arch,
            error: Some(format!("Failed to read {cpuinfo_path}: {error}")),
            flags_missing_for_next_level: None,
            x86_64_level: None,
        },
    }
}

/// The running kernel's architecture. `/proc/sys/kernel/arch` (Linux 6.1+) is
/// preferred; `uname` is the fallback. The binary's compile-time architecture
/// is deliberately not used because e.g. an ARMv7 build may run on aarch64.
fn kernel_arch(kernel_arch_path: &str) -> Option<String> {
    std::fs::read_to_string(kernel_arch_path)
        .ok()
        .and_then(|value| nonempty(value.trim()))
        .or_else(uname_machine)
}

fn uname_machine() -> Option<String> {
    // SAFETY: `utsname` is plain old data, so a zeroed value is valid, and
    // `uname` only writes NUL-terminated strings into the provided struct.
    let mut name: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut name) } != 0 {
        return None;
    }
    let bytes: Vec<u8> = name
        .machine
        .iter()
        .take_while(|&&byte| byte != 0)
        .map(|&byte| byte as u8)
        .collect();
    nonempty(String::from_utf8_lossy(&bytes).trim())
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}

pub fn cpu_from_cpuinfo(arch: Option<String>, content: &str) -> CpuData {
    let is_x86_64 = arch.as_deref() == Some("x86_64");
    if !is_x86_64 {
        return CpuData {
            arch,
            error: None,
            flags_missing_for_next_level: None,
            x86_64_level: None,
        };
    }

    let Some(flags) = common_flags(content) else {
        return CpuData {
            arch,
            error: Some("No CPU flags were found in /proc/cpuinfo".to_string()),
            flags_missing_for_next_level: None,
            x86_64_level: None,
        };
    };

    let (level, missing) = x86_64_level(&flags);
    CpuData {
        arch,
        error: None,
        flags_missing_for_next_level: Some(missing),
        x86_64_level: Some(level),
    }
}

/// Flags shared by every processor. Heterogeneous systems can report
/// different flags per core, and software may run on any of them.
fn common_flags(content: &str) -> Option<BTreeSet<&str>> {
    content
        .lines()
        .filter_map(|line| {
            let (key, value) = line.split_once(':')?;
            (key.trim() == "flags").then(|| value.split_whitespace().collect::<BTreeSet<_>>())
        })
        .reduce(|shared, flags| shared.intersection(&flags).copied().collect())
}

fn x86_64_level(flags: &BTreeSet<&str>) -> (u8, Vec<String>) {
    for (index, required) in X86_64_LEVELS.iter().enumerate() {
        let missing: Vec<String> = required
            .iter()
            .filter(|flag| !flags.contains(*flag))
            .map(|flag| flag.to_string())
            .collect();
        if !missing.is_empty() {
            return (index as u8, missing);
        }
    }
    (X86_64_LEVELS.len() as u8, Vec::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    const V1: &str = "fpu cx8 cmov mmx fxsr sse sse2 syscall lm";
    const V2: &str = "cx16 lahf_lm popcnt pni ssse3 sse4_1 sse4_2";
    const V3: &str = "avx avx2 bmi1 bmi2 f16c fma abm movbe xsave";
    const V4: &str = "avx512f avx512bw avx512cd avx512dq avx512vl";

    fn cpuinfo(flag_lines: &[String]) -> String {
        flag_lines
            .iter()
            .enumerate()
            .map(|(index, flags)| format!("processor\t: {index}\nflags\t\t: {flags}\n\n"))
            .collect()
    }

    fn x86(flag_lines: &[String]) -> CpuData {
        cpu_from_cpuinfo(Some("x86_64".to_string()), &cpuinfo(flag_lines))
    }

    #[test]
    fn reports_each_cumulative_level() {
        let cases = [
            (V1.to_string(), 1),
            (format!("{V1} {V2}"), 2),
            (format!("{V1} {V2} {V3}"), 3),
            (format!("{V1} {V2} {V3} {V4}"), 4),
        ];
        for (flags, level) in cases {
            let cpu = x86(&[flags]);
            assert_eq!(cpu.x86_64_level, Some(level));
            assert_eq!(cpu.error, None);
        }
    }

    #[test]
    fn lists_flags_missing_for_the_next_level() {
        let cpu = x86(&[format!("{V1} {V2} {V3}")]);
        assert_eq!(
            cpu.flags_missing_for_next_level.unwrap(),
            ["avx512bw", "avx512cd", "avx512dq", "avx512f", "avx512vl"]
        );
        let top = x86(&[format!("{V1} {V2} {V3} {V4}")]);
        assert_eq!(top.flags_missing_for_next_level, Some(Vec::new()));
    }

    #[test]
    fn ivy_bridge_with_rdrand_is_v2() {
        // The former Saltbox map reported this CPU as x86-64-v3.
        let cpu = x86(&[format!("{V1} {V2} avx f16c rdrand xsave")]);
        assert_eq!(cpu.x86_64_level, Some(2));
    }

    #[test]
    fn haswell_with_tsx_is_v3_not_v4() {
        // The former Saltbox map treated TSX (hle/rtm) as x86-64-v4.
        let cpu = x86(&[format!("{V1} {V2} {V3} hle rtm")]);
        assert_eq!(cpu.x86_64_level, Some(3));
    }

    #[test]
    fn avx512_without_tsx_is_v4() {
        let cpu = x86(&[format!("{V1} {V2} {V3} {V4}")]);
        assert_eq!(cpu.x86_64_level, Some(4));
    }

    #[test]
    fn levels_are_cumulative() {
        let without_cx16 = format!("{V1} {V2} {V3} {V4}").replace("cx16 ", "");
        let cpu = x86(&[without_cx16]);
        assert_eq!(cpu.x86_64_level, Some(1));
        assert_eq!(cpu.flags_missing_for_next_level.unwrap(), ["cx16"]);
    }

    #[test]
    fn uses_flags_shared_by_every_processor() {
        let full = format!("{V1} {V2} {V3}");
        let without_avx2 = full.replace("avx2 ", "");
        let cpu = x86(&[full, without_avx2]);
        assert_eq!(cpu.x86_64_level, Some(2));
        assert_eq!(cpu.flags_missing_for_next_level.unwrap(), ["avx2"]);
    }

    #[test]
    fn reports_zero_when_the_baseline_is_incomplete() {
        let cpu = x86(&["fpu sse".to_string()]);
        assert_eq!(cpu.x86_64_level, Some(0));
        assert!(cpu
            .flags_missing_for_next_level
            .unwrap()
            .contains(&"lm".to_string()));
    }

    #[test]
    fn other_architectures_have_no_level_and_no_error() {
        let cpu = cpu_from_cpuinfo(
            Some("aarch64".to_string()),
            "processor\t: 0\nFeatures\t: fp asimd evtstrm aes\n",
        );
        assert_eq!(
            cpu,
            CpuData {
                arch: Some("aarch64".to_string()),
                error: None,
                flags_missing_for_next_level: None,
                x86_64_level: None,
            }
        );
    }

    #[test]
    fn x86_without_flags_reports_an_error() {
        let cpu = cpu_from_cpuinfo(Some("x86_64".to_string()), "");
        assert_eq!(cpu.x86_64_level, None);
        assert!(cpu.error.is_some());
    }

    #[test]
    fn unreadable_cpuinfo_reports_an_error() {
        let directory = tempfile::tempdir().unwrap();
        let arch = directory.path().join("arch");
        std::fs::write(&arch, "x86_64\n").unwrap();
        let cpu = get_cpu(
            directory.path().join("missing").to_str().unwrap(),
            arch.to_str().unwrap(),
        );
        assert_eq!(cpu.arch.as_deref(), Some("x86_64"));
        assert!(cpu.error.unwrap().contains("Failed to read"));
    }

    #[test]
    fn falls_back_to_uname_when_kernel_arch_is_unavailable() {
        assert_eq!(kernel_arch("/nonexistent/arch"), uname_machine());
        assert!(uname_machine().is_some());
    }
}
