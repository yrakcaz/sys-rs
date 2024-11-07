use std::process::Command;

pub fn test_no_args(path: &str) {
    let output = Command::new(path).output().expect("Failed to run binary");

    assert!(
        !output.status.success(),
        "binary execution should have failed"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(stdout.is_empty(), "stdout: {}", stdout);
    assert!(
        stderr.contains(format!("Usage: {} command [args]", path).as_str()),
        "stderr: {}",
        stderr
    );
    assert!(
        stderr.contains("Error: EINVAL: Invalid argument"),
        "stderr: {}",
        stderr
    );
}
