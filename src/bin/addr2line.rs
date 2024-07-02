use nix::unistd::Pid;

use sys_rs::{
    cov,
    diag::Result,
    input::{args, env},
    process,
    trace,
};

struct Wrapper {
    tracer: cov::Tracer,
}

impl Wrapper {
    pub fn new(path: &str) -> Result<Self> {
        Ok(Self {
            tracer: cov::Tracer::new(path)?,
        })
    }
}

impl trace::Tracer for Wrapper {
    fn trace(&self, child: Pid) -> Result<()> {
        let process = process::Info::build(self.tracer.path(), child)?;
        let mut cached = cov::Cached::default();
        cached.trace(&self.tracer, &process)
    }
}

fn main() -> Result<()> {
    let args = args()?;
    trace::run::<Wrapper>(&Wrapper::new(args[0].to_str()?)?, &args, &env()?)
}
