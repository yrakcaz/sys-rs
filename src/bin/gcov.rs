use nix::unistd::Pid;
use std::{
    fs::File,
    io::{BufRead, BufReader, Write},
    process::exit,
};

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

fn write_cov_line(
    out: &mut File,
    fmt: &str,
    i: usize,
    line: &str,
) -> std::io::Result<()> {
    writeln!(out, "{fmt:>9}:{i:>5}:{line:<}")
}

fn process_file(path: &str, cached: &Cached) -> Result<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let out_path = format!("{path}.cov");

    if let Ok(mut out) = File::create(&out_path) {
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

        eprintln!("\nFile: '{path}'");
        eprintln!("Lines executed: {percentage:.2}% of {i}");
        eprintln!("Creating '{out_path}'");
    } else {
        eprintln!("Warning: {out_path}: Could not create coverage file");
    }

    Ok(())
}

impl trace::Tracer for Wrapper {
    fn trace(&self, pid: Pid) -> Result<i32> {
        let process = process::Info::build(self.tracer.path(), pid)?;
        let mut cached = Cached::default();
        let ret = cached.trace_with_default_progress(&self.tracer, &process)?;
        for path in cached.files() {
            process_file(path, &cached)?;
        }
        Ok(ret)
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
