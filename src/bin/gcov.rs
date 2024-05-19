use nix::unistd::Pid;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
};

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
    // FIXME facto
    fn trace(&self, child: Pid) -> Result<()> {
        let mut cached = trace::cov::Cached::new();
        if let Ok(_) = cached.trace(&self.tracer, child) {
            for path in cached.files().iter() {
                let file = File::open(&path)?;
                let reader = BufReader::new(file);

                let out = File::create(format!("{path}.cov"));
                if let Err(_) = out {
                    continue;
                }
                let mut out = out?;
                let mut i = 0;
                let mut covered = 0;

                for line in reader.lines() {
                    i += 1;
                    let line = line?;
                    let mut write_cov_line = |fmt: &str| {
                        writeln!(out, "{:<10}{i}:{line}", format!("{}:", fmt))
                    };

                    if let Some(count) = cached.coverage(path.to_string(), i) {
                        write_cov_line(&format!("{count}"))?;
                        covered += 1;
                    } else {
                        write_cov_line("-")?;
                    }
                }

                let percentage = (covered as f64 / i as f64) * 100.0;
                println!();
                println!("File: '{path}'");
                println!("Lines executed: {percentage:.2}% of {i}");
                println!("Creating '{path}.gcov'");
            }

            Ok(())
        } else {
            trace::cov::trace_with_basic_print(&self.tracer, child)
        }
    }
}

fn main() -> Result<()> {
    let args = args()?;
    trace::run::<Wrapper>(&Wrapper::new(args[0].to_str()?)?, &args, &env()?)
}
