use std::collections::BTreeMap;

use crate::{
    diag::Result,
    handler::{self, CommandFn},
    param::{Extend, Join, Type, Value},
    progress::State,
};

#[derive(PartialEq, Debug)]
enum Status {
    Handled,
    NotHandled,
}

enum Node {
    Command(CommandFn, Vec<Type>),
    Subcommands(Registry),
    Alias(&'static str),
    HelpCommand,
}

impl Node {
    fn command_no_params(f: CommandFn) -> Self {
        Node::Command(f, vec![])
    }
}

/// Command registry describing the available REPL commands and their
/// parameter signatures.
///
/// The `Registry` stores command nodes (concrete commands, subcommand groups
/// and aliases) in a deterministic `BTreeMap` so help/usage output is stable.
pub struct Registry {
    // Using a BTreeMap to have a deterministic order for display purposes
    nodes: BTreeMap<&'static str, Vec<Node>>,
}

impl Registry {
    fn new() -> Self {
        Self {
            nodes: BTreeMap::new(),
        }
    }

    fn register(mut self, name: &'static str, node: Node) -> Self {
        self.nodes.entry(name).or_default().push(node);
        self
    }

    fn alias(mut self, alias: &'static str, target: &'static str) -> Self {
        self.nodes
            .entry(alias)
            .or_default()
            .push(Node::Alias(target));
        self
    }

    fn walk<'a, F>(&'a self, prefix: &mut Vec<&'a str>, f: &mut F)
    where
        F: FnMut(&[&'a str], Option<&'a [Type]>),
    {
        for (name, nodes) in &self.nodes {
            if nodes.iter().all(|n| matches!(n, Node::Alias(_))) {
                continue;
            }

            if !name.is_empty() {
                prefix.push(name);
            }

            for entry in nodes {
                match entry {
                    Node::Command(_, param_types) => f(prefix, Some(param_types)),
                    Node::Subcommands(sub) => sub.walk(prefix, f),
                    Node::Alias(_) => {}
                    Node::HelpCommand => f(&[*name], None),
                }
            }

            if !name.is_empty() {
                prefix.pop();
            }
        }
    }

    fn collect<F>(&self, mut f: F)
    where
        F: FnMut(&[&str], Option<&[Type]>),
    {
        let mut prefix = Vec::new();
        self.walk(&mut prefix, &mut f);
    }

    #[must_use]
    /// Return a list of concrete command spellings suitable for completion.
    ///
    /// Each entry is a space-separated command spelling (including parent
    /// subcommands). The results are deduplicated and are intended to be used
    /// by the REPL completion helper.
    ///
    /// # Returns
    ///
    /// A deduplicated `Vec<String>` containing space-separated command
    /// spellings (including parent subcommands) suitable for use by the
    /// REPL completion helper.
    pub fn completions(&self) -> Vec<String> {
        let mut out = Vec::new();

        self.collect(|names, _| {
            out.push(names.join(" "));
        });

        out.dedup();
        out
    }

    #[must_use]
    /// Return human-friendly usage lines for every command.
    ///
    /// Each usage entry contains the full command spelling (including parent
    /// subcommands) and the parameter signature (e.g. `breakpoint <address>`).
    /// This is suitable for printing when the user requests help.
    ///
    /// # Returns
    ///
    /// A `Vec<String>` where each entry contains a command spelling and its
    /// parameter signature (for example `breakpoint <address>`), intended
    /// for help output.
    pub fn usages(&self) -> Vec<String> {
        let mut out = Vec::new();

        self.collect(|names, param_types| {
            let mut usage = names.join(" ");
            if let Some(params) = param_types {
                if !params.is_empty() {
                    let params_str = params
                        .iter()
                        .map(std::string::ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(" ");
                    usage.push(' ');
                    usage.push_str(&params_str);
                }
            }

            out.push(usage);
        });

        out
    }

    fn parse_params<'a>(
        param_types: &[Type],
        params: &'a [&'a str],
    ) -> Vec<Value<'a>> {
        let mut parsed = Vec::new();

        for (i, param_type) in param_types.iter().enumerate() {
            if let Ok(value) = Value::new(param_type, params[i]) {
                parsed.push(value);
            }
        }

        parsed
    }

    fn handle_command(
        handler: CommandFn,
        param_types: &[Type],
        rest: &[&str],
        state: &mut State,
    ) -> Result<Status> {
        let mut status = Status::NotHandled;

        let num_params = param_types.len();
        if rest.len() == num_params {
            let parsed = Self::parse_params(param_types, rest);
            if parsed.len() == num_params {
                handler(&parsed, state)?;
                status = Status::Handled;
            }
        }

        Ok(status)
    }

    fn handle_subcommands(
        registry: &Registry,
        path: &[Value],
        first: &str,
        rest: &[&str],
        state: &mut State,
    ) -> Result<()> {
        let path = path.extend(first, &[]);
        if rest.is_empty() {
            handler::do_ambiguous(&path, state)
        } else {
            registry.dispatch(rest, &path, state)
        }
    }

    fn handle_help(
        &self,
        path: &[Value],
        first: &str,
        rest: &[&str],
        state: &mut State,
    ) -> Result<()> {
        if rest.is_empty() {
            let commands = self.usages();
            let commands: Vec<Value> =
                commands.iter().map(|s| Value::String(s)).collect();
            handler::do_help(&commands, state)
        } else {
            let path = path.extend(first, rest);
            handler::do_unknown(&path, state)
        }
    }

    fn handle_no_entry(
        &self,
        path: &[Value],
        first: &str,
        rest: &[&str],
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
                let path = path.extend(first, &[]);
                handler::do_ambiguous(&path, state)
            }
            _ => {
                let path = path.extend(first, rest);
                handler::do_unknown(&path, state)
            }
        }
    }

    fn handle_node(
        &self,
        node: &Node,
        path: &[Value],
        first: &str,
        rest: &[&str],
        state: &mut State,
    ) -> Result<bool> {
        match node {
            Node::Command(handler, param_types) => {
                match Self::handle_command(*handler, param_types, rest, state)? {
                    Status::Handled => Ok(true),
                    Status::NotHandled => Ok(false),
                }
            }
            Node::Subcommands(registry) => {
                let res =
                    Self::handle_subcommands(registry, path, first, rest, state);
                Ok(res.is_ok())
            }
            Node::Alias(target) => {
                let mut new_args = vec![*target];
                new_args.extend_from_slice(rest);
                let res = self.dispatch(&new_args, path, state);
                Ok(res.is_ok())
            }
            Node::HelpCommand => {
                let res = self.handle_help(path, first, rest, state);
                Ok(res.is_ok())
            }
        }
    }

    fn dispatch(
        &self,
        args: &[&str],
        path: &[Value],
        state: &mut State,
    ) -> Result<()> {
        match args.split_first() {
            Some((first, rest)) => match self.nodes.get(*first) {
                Some(nodes) => {
                    let mut handled = false;
                    for node in nodes {
                        handled |=
                            self.handle_node(node, path, first, rest, state)?;
                    }
                    if !handled {
                        let path = path.extend(first, &[]);
                        let args = format!("{}: {}", path.join(" "), rest.join(" "));
                        handler::do_invalid_arguments(
                            &[Value::String(&args)],
                            state,
                        )?;
                    }
                    Ok(())
                }
                None => self.handle_no_entry(path, first, rest, state),
            },
            None => handler::do_nothing(&[], state),
        }
    }

    /// Parse `input` and dispatch the corresponding command handler.
    ///
    /// # Arguments
    ///
    /// * `input` - The raw user input line (e.g. `breakpoint 0x400123`).
    /// * `state` - Mutable reference to runtime `State` used by handlers.
    ///
    /// # Errors
    ///
    /// Returns an error if dispatching a command fails; handlers return
    /// `Result` which is propagated to the caller.
    pub fn run(&self, input: &str, state: &mut State) -> Result<()> {
        let args: Vec<&str> = input.split_whitespace().collect();
        self.dispatch(&args, &[], state)?;
        Ok(())
    }
}

impl Default for Registry {
    fn default() -> Self {
        let info_registry = Registry::new()
            .register(
                "breakpoints",
                Node::command_no_params(handler::do_info_breakpoints),
            )
            .register("memory", Node::command_no_params(handler::do_info_memory))
            .register(
                "registers",
                Node::command_no_params(handler::do_info_registers),
            );

        let layout_registry = Registry::new()
            .register("asm", Node::command_no_params(handler::do_layout_asm))
            .register("src", Node::command_no_params(handler::do_layout_src));

        Registry::new()
            .register("backtrace", Node::command_no_params(handler::do_backtrace))
            .alias("bt", "backtrace")
            .register(
                "breakpoint",
                Node::command_no_params(handler::do_breakpoint),
            )
            .register(
                "breakpoint",
                Node::Command(handler::do_breakpoint, vec![Type::Address]),
            )
            .alias("b", "breakpoint") // Remove ambiguity with backtrace
            .register("continue", Node::command_no_params(handler::do_continue))
            .register("delete", Node::Command(handler::do_delete, vec![Type::Id]))
            .register(
                "examine",
                Node::Command(
                    handler::do_examine,
                    vec![Type::Format, Type::Size, Type::Address],
                ),
            )
            .alias("x", "examine")
            .register("help", Node::HelpCommand)
            .register("info", Node::Subcommands(info_registry))
            .register("layout", Node::Subcommands(layout_registry))
            .register("list", Node::command_no_params(handler::do_list))
            .alias("l", "list") // Remove ambiguity with layout
            .register("quit", Node::command_no_params(handler::do_quit))
            .register("step", Node::command_no_params(handler::do_step))
            .register("next", Node::command_no_params(handler::do_next))
            .register(
                "tbreakpoint",
                Node::command_no_params(handler::do_tbreakpoint),
            )
            .register(
                "tbreakpoint",
                Node::Command(handler::do_tbreakpoint, vec![Type::Address]),
            )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use nix::unistd::Pid;

    use crate::{
        param::{Type, Value},
        progress::{Execution, State},
    };

    #[test]
    fn test_registry_completions_and_usages() {
        let reg = Registry::new()
            .register("foo", Node::command_no_params(handler::do_nothing))
            .register(
                "bar",
                Node::Command(handler::do_nothing, vec![Type::Address, Type::Id]),
            );

        let comps = reg.completions();
        assert!(comps.contains(&"foo".to_string()));
        assert!(comps.contains(&"bar".to_string()));

        let usages = reg.usages();
        assert!(usages.iter().any(|s| s.starts_with("bar ")));
    }

    #[test]
    fn test_handle_command_param_matching() {
        fn my_handler(_args: &[Value], _state: &mut State) -> Result<()> {
            Ok(())
        }

        let mut state = State::new(Pid::from_raw(1), None);
        let res = Registry::handle_command(
            my_handler,
            &[Type::Address],
            &["0x100"],
            &mut state,
        )
        .expect("handle_command failed");
        assert_eq!(res, Status::Handled);

        let res = Registry::handle_command(
            my_handler,
            &[Type::Address, Type::Id],
            &["0x100"],
            &mut state,
        )
        .expect("handle_command failed");
        assert_eq!(res, Status::NotHandled);
    }

    #[test]
    fn test_handle_no_entry_ambiguous() {
        let reg = Registry::new()
            .register("foo", Node::command_no_params(handler::do_nothing))
            .register("fop", Node::command_no_params(handler::do_nothing));

        let mut state = State::new(Pid::from_raw(1), None);
        reg.dispatch(&["fo"], &[], &mut state)
            .expect("dispatch failed");
        assert!(matches!(state.execution(), Execution::Skip));
    }

    #[test]
    fn test_alias_dispatch() {
        let reg = Registry::new()
            .register("target", Node::command_no_params(handler::do_nothing))
            .alias("a", "target");

        let mut state = State::new(Pid::from_raw(1), None);
        reg.dispatch(&["a"], &[], &mut state)
            .expect("dispatch failed");
        assert!(matches!(state.execution(), Execution::Skip));
    }

    #[test]
    fn test_handle_help_and_run() {
        let reg = Registry::new().register("help", Node::HelpCommand);

        let mut state = State::new(Pid::from_raw(1), None);
        reg.dispatch(&["help"], &[], &mut state)
            .expect("dispatch failed");
        assert!(matches!(state.execution(), Execution::Skip));

        let mut state2 = State::new(Pid::from_raw(1), None);
        reg.run("help", &mut state2).expect("run failed");
        assert!(matches!(state2.execution(), Execution::Skip));
    }
}
