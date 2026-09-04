use std::process::Command;

#[test]
fn version_prints_only_the_compiled_version() {
    // Catches version handling that falls through to fact collection and emits JSON.
    let output = Command::new(env!("CARGO_BIN_EXE_saltbox-facts"))
        .arg("--version")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert_eq!(
        output.stdout,
        format!("{}\n", env!("CARGO_PKG_VERSION")).as_bytes()
    );
    assert!(output.stderr.is_empty());
    assert!(!output.stdout.contains(&b'{'));
}
