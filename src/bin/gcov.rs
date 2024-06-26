use nix::unistd::Pid;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
};

use sys_rs::{
    cov,
    diag::Result,
    input::{args, env},
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

fn write_cov_line(
    out: &mut File,
    fmt: &str,
    i: usize,
    line: &str,
) -> std::io::Result<()> {
    writeln!(out, "{:<10}{i}:{line}", format!("{}:", fmt))
}

fn process_file(path: &str, cached: &cov::Cached) -> Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let out_path = format!("{path}.cov");

    match File::create(&out_path) {
        Ok(mut out) => {
            let mut i = 0;
            let mut covered = 0;

            for line in reader.lines() {
                i += 1;
                let line = line?;
                if let Some(count) = cached.coverage(path.to_string(), i) {
                    write_cov_line(&mut out, &format!("{count}"), i, &line)?;
                    covered += 1;
                } else {
                    write_cov_line(&mut out, "-", i, &line)?;
                }
            }

            #[allow(clippy::cast_precision_loss)]
            let percentage = (f64::from(covered) / i as f64) * 100.0;
            println!("\nFile: '{path}'");
            println!("Lines executed: {percentage:.2}% of {i}");
            println!("Creating '{out_path}'");

            Ok(())
        }
        Err(_) => Ok(()), // Continue on file creation error
    }
}

impl trace::Tracer for Wrapper {
    fn trace(&self, child: Pid) -> Result<()> {
        let mut cached = cov::Cached::default();
        if let Ok(()) = cached.trace(&self.tracer, child) {
            for path in cached.files() {
                process_file(path, &cached)?;
            }

            Ok(())
        } else {
            cov::trace_with_simple_print(&self.tracer, child)
        }
    }
}

fn main() -> Result<()> {
    let args = args()?;
    trace::run::<Wrapper>(&Wrapper::new(args[0].to_str()?)?, &args, &env()?)
}
