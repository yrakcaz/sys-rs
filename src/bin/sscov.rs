use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{wait, WaitStatus},
    },
    unistd::Pid,
};

use sys_rs::{
    asm, breakpoint,
    diag::Result,
    elf,
    input::{args, env},
    trace,
};

struct Tracer {
    elf: elf::Reader,
    parser: asm::Parser,
}

impl Tracer {
    fn new(path: &str) -> Result<Self> {
        Ok(Self {
            elf: elf::Reader::build(path)?,
            parser: asm::Parser::new()?,
        })
    }
}

impl trace::Tracer for Tracer {
    fn trace(&self, child: Pid) -> Result<()> {
        let mut breakpoint_mgr = breakpoint::Manager::new(child);

        let mut startup_complete = false;
        let mut last_instruction: Option<asm::instruction::Wrapper> = None;

        wait()?;
        ptrace::step(child, None)?;
        loop {
            let status = wait()?;
            match status {
                WaitStatus::Stopped(_, Signal::SIGTRAP) => {
                    let mut regs = ptrace::getregs(child)?;
                    breakpoint_mgr.handle_breakpoint(&mut regs)?;

                    let rip = regs.rip;
                    if let Some(bytes) = self.elf.get_bytes_from_text(rip) {
                        let instruction =
                            self.parser.get_instruction_from(bytes, rip)?;
                        println!("{instruction}");
                        last_instruction = Some(instruction);
                    } else if let Some(instruction) = last_instruction.as_ref() {
                        if instruction.is_call() {
                            #[allow(clippy::cast_sign_loss)]
                            let ret = ptrace::read(
                                child,
                                regs.rsp as ptrace::AddressType,
                            )? as u64;

                            // Keep single stepping after the first call as it is
                            // likely to be part of the startup routine so it
                            // might never return.
                            if self.elf.is_in_text_section(ret) && startup_complete {
                                breakpoint_mgr.set_breakpoint(ret)?;
                                ptrace::cont(child, None)?;
                                continue;
                            }
                            startup_complete = true;
                        }
                        last_instruction = None;
                    }

                    ptrace::step(child, None)?;
                }
                WaitStatus::Stopped(_, signal) => ptrace::cont(child, signal)?,
                _ if Tracer::terminated(status) => break,
                _ => {}
            }
        }

        Ok(())
    }
}

fn main() -> Result<()> {
    let args = args()?;
    trace::run::<Tracer>(&Tracer::new(args[0].to_str()?)?, &args, &env()?)
}
