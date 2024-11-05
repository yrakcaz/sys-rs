use std::process::Command;

#[test]
fn test_strace_no_args() {
    let bin = env!("CARGO_BIN_EXE_strace-rs");
    let output = Command::new(bin).output().expect("Failed to run binary");

    assert!(
        !output.status.success(),
        "Binary execution should have failed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stdout.is_empty(), "stdout: {}", stdout);
    assert!(
        stderr.contains(format!("Usage: {} command [args]", bin).as_str()),
        "stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("Error: EINVAL: Invalid argument"),
        "stderr: {}",
        stderr
    );
}

#[test]
fn test_strace_basic() {
    let bin = env!("CARGO_BIN_EXE_strace-rs");
    let test_bin = "ls";
    let output = Command::new(bin)
        .arg(test_bin)
        .output()
        .expect("Failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);

    let ref_output = Command::new("strace")
        .arg(test_bin)
        .output()
        .expect("Failed to run binary");

    assert!(output.status.success());

    let ref_stderr = String::from_utf8_lossy(&ref_output.stderr);

    let extract_syscalls = |output: &str| -> Vec<String> {
        output
            .lines()
            .filter_map(|line| {
                line.split_once('(').map(|(syscall, _)| syscall.to_string())
            })
            .collect()
    };

    let syscalls = extract_syscalls(&stderr);
    let ref_syscalls = extract_syscalls(&ref_stderr);

    for (syscall, ref_syscall) in syscalls.iter().zip(ref_syscalls.iter()) {
        assert_eq!(
            syscall, ref_syscall,
            "Syscall mismatch: {} != {}",
            syscall, ref_syscall
        );
    }
}
