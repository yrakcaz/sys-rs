pub mod testlib;

#[test]
fn test_sscov_no_args() {
    let bin = env!("CARGO_BIN_EXE_sscov-rs");
    testlib::test_no_args(bin);
}

#[test]
fn test_sscov_basic() {
    let bin = env!("CARGO_BIN_EXE_sscov-rs");
    testlib::test_cov(bin);
}
