use nix::errno::Errno;
use rustyline::{
    completion::{Completer, Pair},
    error::ReadlineError,
    highlight::Highlighter,
    hint::Hinter,
    history::FileHistory,
    validate::Validator,
    Context, Editor, Helper,
};

use crate::{
    command::Registry,
    diag::{Error, Result},
    progress::State,
};

struct CmdHelper {
    options: Vec<String>,
}

impl Completer for CmdHelper {
    type Candidate = Pair;

    fn complete(
        &self,
        line: &str,
        pos: usize,
        _: &Context<'_>,
    ) -> rustyline::Result<(usize, Vec<Pair>)> {
        let prefix = line[..pos].split_whitespace().collect::<Vec<_>>().join(" ");
        let input_words: Vec<&str> = prefix.split_whitespace().collect();

        let matches = self
            .options
            .iter()
            .filter(|cmd| {
                let cmd_words: Vec<&str> = cmd.split_whitespace().collect();
                input_words
                    .iter()
                    .zip(cmd_words.iter())
                    .all(|(input, cmd)| cmd.starts_with(input))
                    && input_words.len() <= cmd_words.len()
            })
            .map(|cmd| Pair {
                display: cmd.as_str().to_owned(),
                replacement: cmd.as_str().to_owned(),
            })
            .collect();

        Ok((0, matches))
    }
}

impl Hinter for CmdHelper {
    type Hint = String;
}
impl Highlighter for CmdHelper {}
impl Validator for CmdHelper {}
impl Helper for CmdHelper {}

/// REPL runner that manages the line-editor and command registry.
///
/// The `Runner` owns a `rustyline::Editor` configured with a simple
/// `CmdHelper` for tab-completion and a `Registry` of available commands.
/// Construct a `Runner` with `Runner::new()` and call `run(state)` to read
/// a single line of input and dispatch the corresponding command.
pub struct Runner {
    readline: Editor<CmdHelper, FileHistory>,
    registry: Registry,
}

impl Runner {
    /// Construct a new REPL `Runner` with default command registry and
    /// line-editing helper.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying `rustyline::Editor` cannot be
    /// created.
    ///
    /// # Returns
    ///
    /// A `Result` containing the newly created `Runner`.
    pub fn new() -> Result<Self> {
        let registry = Registry::default();
        let mut readline = Editor::new()?;
        readline.set_helper(Some(CmdHelper {
            options: registry.completions(),
        }));

        Ok(Self { readline, registry })
    }

    /// Read a single line from the user and dispatch the corresponding
    /// command.
    ///
    /// # Arguments
    ///
    /// * `state` - Mutable reference to the runtime `State` passed to
    ///   command handlers.
    ///
    /// # Errors
    ///
    /// Returns an error when readline operations fail or when command
    /// dispatching returns an error.
    ///
    /// # Returns
    ///
    /// Returns the `Result` returned by the invoked command handler.
    pub fn run(&mut self, state: &mut State) -> Result<()> {
        let readline = self.readline.readline("dbg> ");
        match readline {
            Ok(line) => {
                let trimmed = line.trim();
                let input = if trimmed.is_empty() {
                    self.readline
                        .history()
                        .into_iter()
                        .last()
                        .map_or("", |s| s.trim())
                } else {
                    self.readline.add_history_entry(trimmed)?;
                    trimmed
                };

                self.registry.run(input, state)
            }
            Err(ReadlineError::Interrupted | ReadlineError::Eof) => {
                self.registry.run("quit", state)
            }
            _ => Err(Error::from(Errno::EIO)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cmdhelper_complete_prefix() {
        let helper = CmdHelper {
            options: vec!["foo bar".into(), "foo baz".into(), "other".into()],
        };

        let line = "fo";
        let pos = 2usize;
        let prefix = line[..pos].split_whitespace().collect::<Vec<_>>().join(" ");
        let input_words: Vec<&str> = prefix.split_whitespace().collect();

        let matches: Vec<String> = helper
            .options
            .iter()
            .filter(|cmd| {
                let cmd_words: Vec<&str> = cmd.split_whitespace().collect();
                input_words
                    .iter()
                    .zip(cmd_words.iter())
                    .all(|(input, cmd)| cmd.starts_with(input))
                    && input_words.len() <= cmd_words.len()
            })
            .cloned()
            .collect();

        assert!(matches.contains(&"foo bar".to_string()));
        assert!(matches.contains(&"foo baz".to_string()));
    }

    #[test]
    fn test_runner_new() {
        let _runner = Runner::new().expect("runner new");
    }
}
