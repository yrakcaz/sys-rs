use nix::sys::ptrace;
use std::collections::HashMap;

use crate::{diag::Result, print::Layout, progress::State};

type CommandFn = fn(&[&str], &mut State) -> Result<()>;

fn do_unknown(args: &[&str], state: &mut State) -> Result<()> {
    eprintln!("Unknown command: {}", args.join(" "));
    state.set_running(false);
    Ok(())
}

fn do_nothing(_: &[&str], state: &mut State) -> Result<()> {
    state.set_running(false);
    Ok(())
}

fn do_continue(_: &[&str], state: &mut State) -> Result<()> {
    ptrace::cont(state.child(), None)?;
    state.set_running(true);
    Ok(())
}

// FIXME need a do_help

fn do_layout_asm(_: &[&str], state: &mut State) -> Result<()> {
    if *state.layout() == Layout::Assembly {
        eprintln!("Already in assembly layout mode");
    } else {
        state.set_layout(Layout::Assembly);
        eprintln!("[Switching to assembly layout mode]");
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
        state.set_layout(Layout::Source);
        eprintln!("[Switching to source layout mode]");
    }

    state.set_running(false);
    Ok(())
}

fn do_step(_: &[&str], state: &mut State) -> Result<()> {
    ptrace::step(state.child(), None)?;
    state.set_running(true);
    Ok(())
}

fn do_quit(_: &[&str], state: &mut State) -> Result<()> {
    state.set_exiting();
    eprintln!("Exiting...");
    Ok(())
}

// FIXME is it correct to use &'static str?
// FIXME verif design
#[derive(Clone)] // FIXME no clone
enum Node {
    Command(CommandFn),
    Subcommands(HashMap<&'static str, Node>),
}

pub struct Registry {
    nodes: HashMap<&'static str, Node>,
}

impl Registry {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
        }
    }

    fn register(mut self, name: &'static str, node: Node) -> Self {
        match node {
            Node::Command(handler) => {
                self.nodes.insert(name, Node::Command(handler));
            }
            Node::Subcommands(subcommands) => {
                self.nodes.insert(name, Node::Subcommands(subcommands));
            }
        }
        self
    }

    pub fn run(&self, input: &str, state: &mut State) -> Result<()> {
        // FIXME refactor
        let args: Vec<&str> = input.split_whitespace().collect();
        let command = args.get(0).copied().unwrap_or("");

        match self.nodes.get(command) {
            Some(Node::Command(handler)) => handler(&args, state),
            Some(Node::Subcommands(subs)) => {
                let sub_input =
                    args.get(1..).map(|a| a.join(" ")).unwrap_or_default();
                let sub_registry = Registry {
                    nodes: subs.clone(),
                };
                sub_registry.run(&sub_input, state)
            }
            None => {
                let matches = self
                    .nodes
                    .keys()
                    .filter(|name| name.starts_with(command))
                    .collect::<Vec<_>>();
                match matches.len() {
                    1 => {
                        let sub_input = std::iter::once(*matches[0])
                            .chain(args.get(1..).unwrap_or(&[]).iter().copied())
                            .collect::<Vec<_>>()
                            .join(" ");
                        self.run(&sub_input, state)
                    }
                    n if n > 1 => {
                        eprintln!(
                            // FIXME broken for subcommands (e.g. try just "lay")
                            "Ambiguous command '{}'. Possible completions: {:?}",
                            command, matches
                        );
                        do_unknown(&args, state)
                    }
                    _ => do_unknown(&args, state),
                }
            }
        }
    }
}

pub fn registry() -> Registry {
    Registry::new()
        .register("", Node::Command(do_nothing))
        .register("continue", Node::Command(do_continue))
        .register("step", Node::Command(do_step))
        .register("quit", Node::Command(do_quit))
        .register(
            "layout",
            Node::Subcommands({
                let mut layout_nodes = HashMap::new();
                layout_nodes.insert("asm", Node::Command(do_layout_asm));
                layout_nodes.insert("src", Node::Command(do_layout_src));
                layout_nodes
            }),
        )
}
