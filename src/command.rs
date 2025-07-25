use nix::sys::ptrace;
use std::{
    collections::BTreeMap,
    fs::read_to_string,
};

use crate::{diag::Result, print::Layout, progress::State};

type CommandFn = fn(&[&str], &mut State) -> Result<()>;

// FIXME Some of this file might need to be pulled out : the whole commands themselves and/or some of their content e.g. ptrace calls, process specific stuff...
// FIXME should all commands somehow be "inheriting" from do_nothing or do_somthing so they can possibly be 1-liners e.g. using traits or closures? don't forget do_help..

fn do_continue(_: &[&str], state: &mut State) -> Result<()> {
    ptrace::cont(state.pid(), None)?;
    state.set_running(true);
    Ok(())
}

fn do_ambiguous(args: &[&str], state: &mut State) -> Result<()> {
    eprintln!("Ambiguous command: {}", args.join(" "));
    state.set_running(false);
    Ok(())
}

fn do_info_memory(_: &[&str], state: &mut State) -> Result<()> {
    print!("{}", read_to_string(format!("/proc/{}/maps", state.pid()))?);
    state.set_running(false);
    Ok(())
}

fn do_info_registers(_: &[&str], state: &mut State) -> Result<()> {
    let regs = ptrace::getregs(state.pid())?; // FIXME there probably is scope for a regs module
    println!( "rip: 0x{:x}", regs.rip);
    println!( "rsp: 0x{:x}", regs.rsp);
    println!( "rbp: 0x{:x}", regs.rbp);
    println!( "eflags: 0x{:x}", regs.eflags);
    println!( "orig_rax: 0x{:x}", regs.orig_rax);
    println!( "rax: 0x{:x}", regs.rax);
    println!( "rbx: 0x{:x}", regs.rbx);
    println!( "rcx: 0x{:x}", regs.rcx);
    println!( "rdx: 0x{:x}", regs.rdx);
    println!( "rdi: 0x{:x}", regs.rdi);
    println!( "rsi: 0x{:x}", regs.rsi);
    println!( "r8: 0x{:x}", regs.r8);
    println!( "r9: 0x{:x}", regs.r9);
    println!( "r10: 0x{:x}", regs.r10);
    println!( "r11: 0x{:x}", regs.r11);
    println!( "r12: 0x{:x}", regs.r12);
    println!( "r13: 0x{:x}", regs.r13);
    println!( "r14: 0x{:x}", regs.r14);
    println!( "r15: 0x{:x}", regs.r15);
    println!( "cs: 0x{:x}", regs.cs);
    println!( "ds: 0x{:x}", regs.ds);
    println!( "es: 0x{:x}", regs.es);
    println!( "fs: 0x{:x}", regs.fs);
    println!( "gs: 0x{:x}", regs.gs);
    println!( "ss: 0x{:x}", regs.ss);
    println!( "fs_base: 0x{:x}", regs.fs_base);
    println!( "gs_base: 0x{:x}", regs.gs_base);
    state.set_running(false);
    Ok(())
}

fn do_layout_asm(_: &[&str], state: &mut State) -> Result<()> {
    if *state.layout() == Layout::Assembly {
        eprintln!("Already in assembly layout mode");
    } else {
        println!("[Switching to assembly layout mode]");
        state.set_layout(Layout::Assembly);
    }

    state.set_running(false);
    Ok(())
}

fn do_layout_src(_: &[&str], state: &mut State) -> Result<()> {
    if *state.initial_layout() == Layout::Assembly {
        eprintln!("No source layout available");
    } else if *state.layout() == Layout::Source {
        eprintln!("Already in source layout mode");
    } else {
        println!("[Switching to source layout mode]");
        state.set_layout(Layout::Source);
    }

    state.set_running(false);
    Ok(())
}

fn do_nothing(_: &[&str], state: &mut State) -> Result<()> {
    state.set_running(false);
    Ok(())
}

fn do_step(_: &[&str], state: &mut State) -> Result<()> {
    ptrace::step(state.pid(), None)?;
    state.set_running(true);
    Ok(())
}

fn do_quit(_: &[&str], state: &mut State) -> Result<()> {
    println!("Exiting...");
    state.set_exiting();
    Ok(())
}

fn do_unknown(args: &[&str], state: &mut State) -> Result<()> {
    eprintln!("Unknown command: {}", args.join(" "));
    state.set_running(false);
    Ok(())
}

enum Node {
    Command(CommandFn),
    Subcommands(Registry),
    HelpCommand,
}

pub struct Registry {
    // Using a BTreeMap to have a deterministic order for display purposes
    nodes: BTreeMap<&'static str, Node>,
}

impl Registry {
    fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
        }
    }

    fn register(mut self, name: &'static str, node: Node) -> Self {
        self.nodes.insert(name, node);
        self
    }

    pub fn commands(&self) -> Vec<String> {
        fn collect(
            node: &Registry,
            prefix: &mut Vec<&'static str>,
            out: &mut Vec<String>,
        ) {
            for (name, entry) in &node.nodes {
                let pushed = if !name.is_empty() {
                    prefix.push(name);
                    true
                } else {
                    false
                };
                match entry {
                    Node::Command(_) | &Node::HelpCommand => {
                        out.push(prefix.join(" "));
                    }
                    Node::Subcommands(registry) => {
                        collect(registry, prefix, out);
                    }
                }
                if pushed {
                    prefix.pop();
                }
            }
        }

        let mut commands = Vec::new();
        let mut prefix = Vec::new();
        collect(self, &mut prefix, &mut commands);
        commands
    }

    fn build_path<'a>(
        path: &'a [&'a str],
        first: &'a str,
        rest: &'a [&'a str],
    ) -> Vec<&'a str> {
        let mut path = path.to_vec();
        path.push(first);
        path.extend_from_slice(rest);
        path
    }

    fn handle_command(
        &self,
        handler: &CommandFn,
        args: &[&str],
        path: &[&str],
        first: &str,
        rest: &[&str],
        state: &mut State,
    ) -> Result<()> {
        if rest.is_empty() {
            handler(args, state)
        } else {
            let path = Self::build_path(path, first, rest);
            do_unknown(&path, state)
        }
    }

    fn handle_subcommands(
        &self,
        registry: &Registry,
        rest: &[&str],
        path: &[&str],
        first: &str,
        state: &mut State,
    ) -> Result<()> {
        let path = Self::build_path(path, first, &[]);
        if rest.is_empty() {
            do_ambiguous(&path, state)
        } else {
            registry.dispatch(rest, &path, state)
        }
    }

    fn handle_help(
        &self,
        args: &[&str],
        path: &[&str],
        first: &str,
        rest: &[&str],
        state: &mut State,
    ) -> Result<()> {
        if rest.is_empty() {
            for command in self.commands() {
                println!("{}", command);
            }
            do_nothing(args, state)
        } else {
            let path = Self::build_path(path, first, rest);
            do_unknown(&path, state)
        }
    }

    fn handle_no_entry(
        &self,
        first: &str,
        rest: &[&str],
        path: &[&str],
        state: &mut State,
    ) -> Result<()> {
        let matches: Vec<_> = self
            .nodes
            .keys()
            .filter(|name| name.starts_with(first))
            .collect();
        match matches.len() {
            1 => {
                let mut args = vec![*matches[0]];
                args.extend_from_slice(rest);
                self.dispatch(&args, path, state)
            }
            n if n > 1 => {
                let path = Self::build_path(path, first, &[]);
                do_ambiguous(&path, state)
            }
            _ => {
                let path = Self::build_path(path, first, rest);
                do_unknown(&path, state)
            }
        }
    }

    fn dispatch(
        &self,
        args: &[&str],
        path: &[&str],
        state: &mut State,
    ) -> Result<()> {
        if let Some((first, rest)) = args.split_first() {
            match self.nodes.get(*first) {
                Some(Node::Command(handler)) => {
                    self.handle_command(handler, args, path, first, rest, state)
                }
                Some(Node::Subcommands(registry)) => {
                    self.handle_subcommands(registry, rest, path, first, state)
                }
                Some(Node::HelpCommand) => {
                    self.handle_help(args, path, first, rest, state)
                }
                None => self.handle_no_entry(first, rest, path, state),
            }
        } else {
            do_nothing(args, state)
        }
    }

    pub fn run(&self, input: &str, state: &mut State) -> Result<()> {
        let args: Vec<&str> = input.split_whitespace().collect();
        self.dispatch(&args, &[], state)
    }
}

impl Default for Registry {
    fn default() -> Self {
        let info_registry = Registry::new()
            .register("memory", Node::Command(do_info_memory))
            .register("registers", Node::Command(do_info_registers));

        let layout_registry = Registry::new()
            .register("asm", Node::Command(do_layout_asm))
            .register("src", Node::Command(do_layout_src));

        Registry::new()
            .register("continue", Node::Command(do_continue))
            .register("help", Node::HelpCommand)
            .register("info", Node::Subcommands(info_registry))
            .register("layout", Node::Subcommands(layout_registry))
            .register("step", Node::Command(do_step))
            .register("quit", Node::Command(do_quit))
    }
}
