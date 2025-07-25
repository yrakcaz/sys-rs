use serial_test::serial;
use std::path::Path;
use std::process::Command;

pub mod testlib;

#[test]
fn test_gcov_no_args() {
    let bin = env!("CARGO_BIN_EXE_gcov-rs");
    testlib::test_no_args(bin);
}
#[test]
fn test_gcov_no_exec() {
    let bin = env!("CARGO_BIN_EXE_gcov-rs");
    testlib::test_no_exec(bin);
}

#[test]
#[serial]
fn test_gcov_basic() {
    let (example_path, example_bin) = testlib::build_example_gdwarf4();
    let bin_path = Path::new(&example_bin);
    let _cleanup = testlib::Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_gcov-rs");
    let output = Command::new(bin)
        .arg(&bin_path)
        .output()
        .expect("Failed to execute binary");
    assert!(output.status.success());

    let cov_path = format!("{}.cov", &example_path);
    assert!(
        Path::new(&cov_path).exists(),
        "{} does not exist",
        &cov_path
    );

    let cov_content =
        std::fs::read_to_string(&cov_path).expect("Failed to read file");
    let ref_path = format!("{}.ref", &cov_path);
    let ref_content =
        std::fs::read_to_string(&ref_path).expect("Failed to read file");
    assert_eq!(
        cov_content, ref_content,
        "Coverage content does not match reference content"
    );

    testlib::test_cov(bin);
}
