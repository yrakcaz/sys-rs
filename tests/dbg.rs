use serial_test::serial;
use std::path::Path;

pub mod testlib;

#[test]
fn test_dbg_no_args() {
    let bin = env!("CARGO_BIN_EXE_dbg-rs");
    testlib::test_no_args(bin);
}

#[test]
fn test_dbg_no_exec() {
    let bin = env!("CARGO_BIN_EXE_dbg-rs");
    testlib::test_no_exec(bin);
}

#[test]
#[serial]
fn test_dbg_basic() {
    let (_, example_bin) = testlib::build_example_gdwarf4();
    let bin_path = Path::new(&example_bin);
    let _cleanup = testlib::Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_dbg-rs");
    let debugging_commands = vec![
        "list",
        "info registers",
        "info memory",
        "breakpoint",
        "info breakpoints",
        "backtrace",
        "layout src",
        "layout asm",
        "step",
        "next",
        "continue",
        "quit",
    ];
    let (stdout, stderr, success) =
        testlib::run_cli_commands(bin, &example_bin, &debugging_commands);
    assert!(
        success,
        "Debugging session should complete successfully. stderr: {}",
        stderr
    );

    let combined_output = format!("{}{}", stdout, stderr);
    assert!(
        combined_output.contains("0x")
            && combined_output.contains("main")
            && combined_output.contains("example.c"),
        "Should show program entry point with address and source info. Output: {}",
        combined_output
    );
    assert!(
        combined_output.contains("rax")
            && combined_output.contains("rip")
            && combined_output.contains("rsp"),
        "Should show register information (x86/x64 registers). Output: {}",
        combined_output
    );
    assert!(
        combined_output.contains("Breakpoint")
            || combined_output.contains("breakpoint")
            || combined_output.contains("set")
            || combined_output.contains("Set"),
        "Should show breakpoint management output. Output: {}",
        combined_output
    );
    assert!(
        combined_output.contains("layout")
            || combined_output.contains("Layout")
            || combined_output.contains("assembly")
            || combined_output.contains("source")
            || combined_output.contains("Switching"),
        "Should show layout switching messages. Output: {}",
        combined_output
    );
    assert!(
        combined_output.contains("Continuing")
            || combined_output.contains("Exiting")
            || combined_output.contains("exited with 0")
            || combined_output.contains("+++")
            || combined_output.contains("Hello, World!"),
        "Should show execution control feedback or program output. Output: {}",
        combined_output
    );
    assert!(
        !combined_output.contains("SIGSEGV")
            && !combined_output.contains("segmentation fault"),
        "Should not crash with segmentation fault. Output: {}",
        combined_output
    );
    assert!(
        !combined_output.contains("SIGABRT") && !combined_output.contains("abort"),
        "Should not abort unexpectedly. Output: {}",
        combined_output
    );
}

#[test]
#[serial]
fn test_dbg_commands() {
    let (_, example_bin) = testlib::build_example_gdwarf4();
    let bin_path = Path::new(&example_bin);
    let _cleanup = testlib::Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_dbg-rs");
    let (_, stderr, success) = testlib::run_cli_commands(
        bin,
        &example_bin,
        &[
            "help",
            "info registers",
            "info memory",
            "list",
            "breakpoint",
            "info breakpoints",
            "layout src",
            "layout asm",
            "backtrace",
            "quit",
        ],
    );

    assert!(
        success,
        "dbg-rs should complete successfully. stderr: {}",
        stderr
    );
}

#[test]
#[serial]
fn test_dbg_examine() {
    let (_, example_bin) = testlib::build_example_gdwarf4();
    let bin_path = Path::new(&example_bin);
    let _cleanup = testlib::Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_dbg-rs");
    let setup_commands = vec!["breakpoint", "info breakpoints", "quit"];
    let (stdout, stderr, success) =
        testlib::run_cli_commands(bin, &example_bin, &setup_commands);
    assert!(
        success,
        "Setup for examine command test should complete successfully. stderr: {}",
        stderr
    );

    let combined_output = format!("{}{}", stdout, stderr);
    let addr = combined_output
        .lines()
        .find_map(|line| {
            let re = regex::Regex::new(r"0x[0-9a-fA-F]+\b").unwrap();
            re.find(line).map(|m| m.as_str().to_string())
        })
        .expect("Could not find breakpoint address in output");

    let examine_x = format!("examine x 4 {}", addr);
    let examine_i = format!("examine i 1 {}", addr);
    let examine_commands = vec![examine_x.as_str(), examine_i.as_str(), "quit"];
    let (stdout, stderr, success) =
        testlib::run_cli_commands(bin, &example_bin, &examine_commands);
    assert!(
        success,
        "Examine command test should complete successfully. stderr: {}",
        stderr
    );

    let combined_output = format!("{}{}", stdout, stderr);
    assert!(
        combined_output.contains("0x")
            || combined_output.contains(":")
            || combined_output.contains("mov")
            || combined_output.contains("push")
            || combined_output.contains("ret"),
        "Should show memory or instruction dump. Output: {}",
        combined_output
    );
    assert!(
        !combined_output.contains("SIGSEGV") && !combined_output.contains("SIGABRT"),
        "Should not crash during examine commands. Output: {}",
        combined_output
    );
}

#[test]
#[serial]
fn test_dbg_delete_breakpoint() {
    let (_, example_bin) = testlib::build_example_gdwarf4();
    let bin_path = Path::new(&example_bin);
    let _cleanup = testlib::Cleanup { path: bin_path };

    let bin = env!("CARGO_BIN_EXE_dbg-rs");
    let breakpoint_commands = vec![
        "breakpoint",
        "tbreakpoint",
        "info breakpoints",
        "delete 1",
        "info breakpoints",
        "quit",
    ];
    let (stdout, stderr, success) =
        testlib::run_cli_commands(bin, &example_bin, &breakpoint_commands);
    assert!(
        success,
        "Breakpoint management test should complete successfully. stderr: {}",
        stderr
    );

    let combined_output = format!("{}{}", stdout, stderr);
    assert!(
        combined_output.contains("Breakpoint")
            || combined_output.contains("breakpoint")
            || combined_output.contains("Num")
            || combined_output.contains("#")
            || combined_output.contains("0x")
            || combined_output.contains("Id"),
        "Should show breakpoint management output. Output: {}",
        combined_output
    );
}
