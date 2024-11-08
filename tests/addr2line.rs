use serial_test::serial;
use std::path::Path;
use std::process::Command;

pub mod testlib;

#[test]
fn test_addr2line_no_args() {
    let bin = env!("CARGO_BIN_EXE_addr2line-rs");
    testlib::test_no_args(bin);
}

#[test]
fn test_addr2line_no_exec() {
    let bin = env!("CARGO_BIN_EXE_addr2line-rs");
    testlib::test_no_exec(bin);
}

#[test]
#[serial]
fn test_addr2line_no_dwarf() {
    let (_, example_bin) = testlib::build_example_no_dwarf();
    let bin_path = Path::new(&example_bin);
    let _cleanup = testlib::Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_addr2line-rs");
    let output = Command::new(bin)
        .arg(&bin_path)
        .output()
        .expect("Failed to execute binary");
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error: ENODATA: No data available"),
        "stderr: {}",
        stderr
    );
}

#[test]
#[serial]
fn test_addr2line_gdwarf5() {
    let (_, example_bin) = testlib::build_example_gdwarf5();
    let bin_path = Path::new(&example_bin);
    let _cleanup = testlib::Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_addr2line-rs");
    let output = Command::new(bin)
        .arg(&bin_path)
        .output()
        .expect("Failed to execute binary");
    assert!(!output.status.success());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Error: ENOEXEC: Exec format error"),
        "stderr: {}",
        stderr
    );
}

#[test]
#[serial]
fn test_addr2line_basic() {
    let (_, example_bin) = testlib::build_example_gdwarf4();
    let bin_path = Path::new(&example_bin);
    let _cleanup = testlib::Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_addr2line-rs");
    let output = Command::new(bin)
        .arg(&bin_path)
        .output()
        .expect("Failed to execute binary");
    assert!(output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    let ref_bin = "addr2line";
    for line in stderr.lines() {
        if let Some(pos) = line.find(':') {
            let addr = &line[..pos];
            let ref_output = Command::new(ref_bin)
                .arg("-e")
                .arg(&bin_path)
                .arg(&addr)
                .output()
                .expect("Failed to run addr2line");
            assert!(ref_output.status.success());

            let ref_stdout = String::from_utf8_lossy(&ref_output.stdout);
            assert!(
                line.contains(ref_stdout.trim()),
                "Mismatch: {} != {}",
                line,
                ref_stdout.trim()
            );
        }
    }
}
