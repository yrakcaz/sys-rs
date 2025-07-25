use nix::sys::ptrace;
use std::{collections::BTreeMap, fs::read_to_string};

use crate::{diag::Result, hwaccess::Registers, print::Layout, progress::State};

type CommandFn = fn(&[&str], &mut State) -> Result<()>;

fn exit_with(args: &[&str], state: &mut State, f: CommandFn) -> Result<()> {
    f(args, state)?;
    state.set_exiting();
    Ok(())
}

fn proceed_with(args: &[&str], state: &mut State, f: CommandFn) -> Result<()> {
    f(args, state)?;
    state.set_running(true);
    Ok(())
}

fn stall_with(args: &[&str], state: &mut State, f: CommandFn) -> Result<()> {
    f(args, state)?;
    state.set_running(false);
    Ok(())
}

fn do_ambiguous(args: &[&str], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, _| {
        eprintln!("Ambiguous command: {}", args.join(" "));
        Ok(())
    })
}

fn do_continue(args: &[&str], state: &mut State) -> Result<()> {
    proceed_with(args, state, |_, state| {
        ptrace::cont(state.pid(), None).map_err(Into::into)
    })
}

fn do_info_memory(args: &[&str], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        print!("{}", read_to_string(format!("/proc/{}/maps", state.pid()))?);
        Ok(())
    })
}

fn do_info_registers(args: &[&str], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        let regs = Registers::read(state.pid())?;
        println!("{regs}");
        Ok(())
    })
}

fn do_layout_asm(args: &[&str], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        if *state.layout() == Layout::Assembly {
            eprintln!("Already in assembly layout mode");
        } else {
            println!("[Switching to assembly layout mode]");
            state.set_layout(Layout::Assembly);
        }
        Ok(())
    })
}

fn do_layout_src(args: &[&str], state: &mut State) -> Result<()> {
    stall_with(args, state, |_, state| {
        if *state.initial_layout() == Layout::Assembly {
            eprintln!("No source layout available");
        } else if *state.layout() == Layout::Source {
            eprintln!("Already in source layout mode");
        } else {
            println!("[Switching to source layout mode]");
            state.set_layout(Layout::Source);
        }
        Ok(())
    })
}

fn do_quit(args: &[&str], state: &mut State) -> Result<()> {
    exit_with(args, state, |_, _| {
        println!("Exiting...");
        Ok(())
    })
}

fn do_step(args: &[&str], state: &mut State) -> Result<()> {
    proceed_with(args, state, |_, state| {
        ptrace::step(state.pid(), None).map_err(Into::into)
    })
}

fn do_unknown(args: &[&str], state: &mut State) -> Result<()> {
    stall_with(args, state, |args, _| {
        eprintln!("Unknown command: {}", args.join(" "));
        Ok(())
    })
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
        path: &[&str],
        first: &str,
        rest: &[&str],
        state: &mut State,
    ) -> Result<()> {
        if rest.is_empty() {
            let commands = self.commands().join("\n");
            stall_with(&[&commands], state, |args, _| {
                println!("{}", args[0]);
                Ok(())
            })
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
                    self.handle_help(path, first, rest, state)
                }
                None => self.handle_no_entry(first, rest, path, state),
            }
        } else {
            stall_with(args, state, |_, _| Ok(()))
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
            .register("quit", Node::Command(do_quit))
            .register("step", Node::Command(do_step))
    }
}
