use capstone::prelude::*;
use goblin::Object;
use std::{fs, process::Command};

mod testlib;

#[test]
fn test_sscov_no_args() {
    let bin = env!("CARGO_BIN_EXE_sscov-rs");
    testlib::test_no_args(bin);
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

#[test]
fn test_sscov_basic() {
    let bin = env!("CARGO_BIN_EXE_sscov-rs");
    let test_bin = "/bin/ls";
    let output = Command::new(bin)
        .arg(test_bin)
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
