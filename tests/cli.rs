use std::process::Command;

#[path = "support/process.rs"]
mod process;

#[test]
fn version_prints_only_the_compiled_version() {
    // Catches version handling that falls through to fact collection and emits JSON.
    let output =
        process::output(Command::new(env!("CARGO_BIN_EXE_saltbox-facts")).arg("--version"));

    assert!(output.status.success(), "{output:?}");
    assert_eq!(
        output.stdout,
        format!("{}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&b'{'));
}
