//! What the library reads from the outside world, captured once by `main` or
//! supplied by a test or an action. The adapters never reach for the process
//! environment themselves.

use std::ffi::OsString;
use std::io::{IsTerminal, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Where stdin comes from.
#[derive(Clone, Debug, Default)]
pub enum Stdin {
    /// Closed, as a pipeline with nothing to say.
    #[default]
    Closed,
    /// Text a test or an action supplies, standing in for a pipe.
    Text(String),
    /// The process's own stdin: what the CLI uses.
    Inherited,
}

/// The environment one run sees: variables, the working directory, whether
/// stdin is a terminal, and stdin's content.
#[derive(Clone, Debug)]
pub struct Inputs {
    vars: Vec<(String, String)>,
    cwd: PathBuf,
    interactive: bool,
    stdin: Stdin,
}

impl Default for Inputs {
    fn default() -> Self {
        Self {
            vars: Vec::new(),
            cwd: PathBuf::from("."),
            interactive: false,
            stdin: Stdin::Closed,
        }
    }
}

impl Inputs {
    /// Capture the process environment; only `main` should need this.
    pub fn capture() -> Self {
        let vars = std::env::vars().collect();
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        Self {
            vars,
            cwd,
            interactive: std::io::stdin().is_terminal(),
            stdin: Stdin::Inherited,
        }
    }

    pub fn with_var(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        let name = name.into();
        self.vars.retain(|(existing, _)| existing != &name);
        self.vars.push((name, value.into()));
        self
    }

    pub fn with_cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = cwd.into();
        self
    }

    pub fn interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    pub fn with_stdin(mut self, stdin: Stdin) -> Self {
        self.stdin = stdin;
        self
    }

    /// A variable's value, as the adapters see it.
    pub fn var(&self, name: &str) -> Option<&str> {
        self.vars
            .iter()
            .find(|(existing, _)| existing == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn var_is_set(&self, name: &str) -> bool {
        self.var(name).is_some_and(|value| !value.trim().is_empty())
    }

    /// Every variable, as `OsString` pairs for a child process.
    pub fn vars_os(&self) -> Vec<(OsString, OsString)> {
        self.vars
            .iter()
            .map(|(name, value)| (name.into(), value.into()))
            .collect()
    }

    pub fn cwd(&self) -> &Path {
        &self.cwd
    }

    pub fn is_interactive(&self) -> bool {
        self.interactive
    }

    pub fn stdin(&self) -> &Stdin {
        &self.stdin
    }

    /// stdin's content, for `--stdin` and pipelines. A closed stdin is empty.
    pub fn read_stdin(&self) -> Result<String> {
        match &self.stdin {
            Stdin::Text(text) => Ok(text.clone()),
            Stdin::Closed => Ok(String::new()),
            Stdin::Inherited => {
                let mut buffer = String::new();
                std::io::stdin()
                    .read_to_string(&mut buffer)
                    .context("cannot read stdin")?;
                Ok(buffer)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vars_are_set_and_replaced_in_order() {
        let inputs = Inputs::default()
            .with_var("A", "1")
            .with_var("B", "2")
            .with_var("A", "3");

        assert_eq!(inputs.var("A"), Some("3"));
        assert_eq!(inputs.var("B"), Some("2"));
        assert_eq!(inputs.var("C"), None);
        assert_eq!(inputs.vars_os().len(), 2);
    }

    #[test]
    fn an_empty_variable_is_not_set() {
        let inputs = Inputs::default().with_var("EMPTY", "   ");

        assert_eq!(inputs.var("EMPTY"), Some("   "));
        assert!(!inputs.var_is_set("EMPTY"));
    }

    #[test]
    fn stdin_text_stands_in_for_a_pipe() {
        let inputs = Inputs::default().with_stdin(Stdin::Text("value\n".into()));

        assert_eq!(inputs.read_stdin().unwrap(), "value\n");
        assert_eq!(Inputs::default().read_stdin().unwrap(), "");
    }
}
