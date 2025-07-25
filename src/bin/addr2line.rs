use nix::unistd::Pid;
use std::process::exit;

use sys_rs::{
    coverage::Cached,
    diag::Result,
    input::{args, env},
    process, profile, trace,
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

impl trace::Tracer for Wrapper {
    fn trace(&self, pid: Pid) -> Result<i32> {
        let process = process::Info::build(self.tracer.path(), pid)?;
        let mut cached = Cached::default();
        cached.trace_with_source_print(&self.tracer, &process)
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
