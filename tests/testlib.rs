use capstone::prelude::*;
use goblin::Object;
use std::{fs, path::Path, process::Command};

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

fn disass(path: &str) -> Vec<String> {
    let capstone = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Att)
        .detail(true)
        .build()
        .expect("Failed to create Capstone object");

    let buffer = fs::read(path).expect("Failed to read binary");

    let mut ret = Vec::new();
    match Object::parse(&buffer).expect("Failed to parse binary") {
        Object::Elf(elf) => {
            for ph in elf.program_headers.iter() {
                if ph.is_executable() {
                    let code = &buffer[ph.file_range()];
                    let instructions = capstone
                        .disasm_all(code, elf.header.e_entry)
                        .expect("Failed to disassemble code");
                    for ins in instructions.iter() {
                        let ins_str = format!(
                            "{}\t{}",
                            ins.mnemonic().unwrap_or(""),
                            ins.op_str().unwrap_or("")
                        );
                        ret.push(String::from(ins_str.trim()));
                    }
                }
            }
        }
        _ => assert!(false, "Unsupported binary format."),
    }

    ret
}

pub fn test_cov(path: &str) {
    let test_bin = "/bin/ls";
    let output = Command::new(path)
        .arg(&test_bin)
        .output()
        .expect("Failed to run binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success());

    let disass = disass(test_bin);
    for line in stderr.lines() {
        if (line.contains("j") || line.contains("call")) && line.contains("0x") {
            continue;
        }
        if line.contains("+++") || line.contains("---") {
            continue;
        }

        if let Some((_, insn)) = line.split_once(' ') {
            let insn_trimmed = insn.trim();
            assert!(
                disass.contains(&insn_trimmed.to_string()),
                "Disassembly does not contain: {}",
                insn_trimmed
            );
        }
    }
}

pub struct Cleanup<'a> {
    pub path: &'a Path,
}

impl<'a> Drop for Cleanup<'a> {
    fn drop(&mut self) {
        if self.path.exists() {
            fs::remove_file(self.path).expect("Failed to clean up compiled binary");
        }

        let path = self.path.with_extension("c.cov");
        if path.exists() {
            fs::remove_file(path).expect("Failed to clean up compiled binary");
        }
    }
}

pub fn build_example() -> (String, String) {
    let root = env!("CARGO_MANIFEST_DIR");
    let example_dir = format!("{}/tests/example", root);
    let example_path = format!("{}/example.c", &example_dir);
    let example_bin = format!("{}/example", &example_dir);
    let output = Command::new("gcc")
        .arg("-gdwarf-4")
        .arg("-no-pie")
        .arg("-o")
        .arg(&example_bin)
        .arg(&example_path)
        .output()
        .expect("Failed to compile binary");
    assert!(
        output.status.success(),
        "Compilation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    (example_path, example_bin)
}
