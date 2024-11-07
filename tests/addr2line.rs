use std::fs;
use std::path::Path;
use std::process::Command;

mod testlib;

#[test]
fn test_addr2line_no_args() {
    let bin = env!("CARGO_BIN_EXE_addr2line-rs");
    testlib::test_no_args(bin);
}

struct Cleanup<'a> {
    path: &'a Path,
}

impl<'a> Drop for Cleanup<'a> {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_file(self.path).expect("Failed to clean up compiled binary");
        }
    }
}

#[test]
fn test_addr2line_basic() {
    let root = env!("CARGO_MANIFEST_DIR");
    let tests_dir = format!("{}/tests", root);
    let path = format!("{}/example.c", tests_dir);
    let test_bin = format!("{}/test_bin", tests_dir);
    let output = Command::new("gcc")
        .arg("-gdwarf-4")
        .arg("-no-pie")
        .arg("-o")
        .arg(&test_bin)
        .arg(&path)
        .output()
        .expect("Failed to compile binary");
    assert!(
        output.status.success(),
        "Compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bin_path = Path::new(&test_bin);
    let _cleanup = Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_addr2line-rs");
    let output = Command::new(bin)
        .arg(bin_path)
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
                .arg(bin_path)
                .arg(addr)
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
