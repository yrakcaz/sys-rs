use nix::unistd::Pid;
use std::process::exit;

use sys_rs::{
    coverage::Cached,
    debug::Dwarf,
    diag::Result,
    input::{args, env},
    process, profile,
    repl::Handler,
    trace,
};

struct Wrapper {
    tracer: profile::Tracer,
}

impl Wrapper {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            tracer: profile::Tracer::new(path)?,
        })
    }
}

// FIXME Re-do complete testing and doc using agent (then update TODO.md..).
//       Pay extra attention to existing one for modified functions/structs...

impl trace::Tracer for Wrapper {
    fn trace(&self, pid: Pid) -> Result<i32> {
        let process = process::Info::build(self.tracer.path(), pid)?;
        let dwarf = Dwarf::build(&process);
        let mut handler = Handler::new()?;
        let mut cached = Cached::default();
        cached.trace_with_custom_progress(
            &self.tracer,
            &process,
            dwarf.as_ref().ok(),
            false,
            |last_instruction, state| handler.handle(last_instruction, state),
        )
    }
}

fn main() -> Result<()> {
    let args = args()?;
    exit(trace::run::<Wrapper>(
        &Wrapper::new(args[0].to_str()?)?,
        &args,
        &env()?,
    )?)
}
