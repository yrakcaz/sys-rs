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
    asm::Instruction,
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

pub struct Handler {
    readline: Editor<CmdHelper, FileHistory>,
    registry: Registry,
}

impl Handler {
    pub fn new() -> Result<Self> {
        let registry = Registry::default();
        let mut readline = Editor::new()?;
        readline.set_helper(Some(CmdHelper {
            options: registry.commands(),
        }));

        Ok(Self { readline, registry })
    }

    pub fn handle(
        &mut self,
        last_instruction: Option<&Instruction>,
        state: &mut State,
    ) -> Result<()> {
        if last_instruction.is_some() {
            let readline = self.readline.readline("dbg> ");
            match readline {
                Ok(line) => {
                    let trimmed = line.trim();
                    let input = if trimmed.is_empty() {
                        self.readline
                            .history()
                            .into_iter()
                            .last()
                            .map(|s| s.trim())
                            .unwrap_or("")
                    } else {
                        self.readline.add_history_entry(trimmed)?;
                        trimmed
                    };

                    self.registry.run(input, state)?;
                }
                Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                    self.registry.run("quit", state)?
                }
                _ => Err(Error::from(Errno::EIO))?,
            }
        }

        Ok(())
    }
}
