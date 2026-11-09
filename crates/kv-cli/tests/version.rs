use std::process::Command;

#[test]
fn version_subcommand_prints_package_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_kv"))
        .arg("version")
        .output()
        .expect("failed to execute kv");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("stdout not utf-8");
    assert_eq!(stdout.trim(), format!("kv {}", env!("CARGO_PKG_VERSION")));
}
