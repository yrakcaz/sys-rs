use nix::{errno::Errno, unistd::Pid};
use std::collections::{hash_map::Entry, HashMap};

use sys_rs::{
    diag::{Error, Result},
    exec::debug::Dwarf,
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
        let mut cache = HashMap::new();
        let dwarf = Dwarf::build(self.tracer.elf())?;

        trace::cov::trace_with(&self.tracer, child, |instruction| {
            let addr = instruction.addr();
            if let Entry::Vacant(_) = cache.entry(addr) {
                let info = dwarf.addr2line(addr)?;
                cache.insert(addr, info);
            }

            if let Some(line) = cache
                .get(&addr)
                .ok_or_else(|| Error::from(Errno::ENODATA))?
            {
                println!("{line}");
            }

            Ok(())
        })
    }
}

fn main() -> Result<()> {
    let args = args()?;
    trace::run::<Wrapper>(&Wrapper::new(args[0].to_str()?)?, &args, &env()?)
}
