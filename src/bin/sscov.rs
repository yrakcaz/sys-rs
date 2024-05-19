use nix::unistd::Pid;

use sys_rs::{
    diag::Result,
    input::{args, env},
    trace,
};

struct Wrapper {
    tracer: trace::cov::Tracer,
}

impl Wrapper {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            tracer: trace::cov::Tracer::new(path)?,
        })
    }
}

impl trace::Tracer for Wrapper {
    fn trace(&self, child: Pid) -> Result<()> {
        trace::cov::trace_with_basic_print(&self.tracer, child)
    }
}

fn main() -> Result<()> {
    let args = args()?;
    trace::run::<Wrapper>(&Wrapper::new(args[0].to_str()?)?, &args, &env()?)
}
