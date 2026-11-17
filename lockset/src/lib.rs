//! Lockset's orchestration as a library: the same command handlers the
//! `lockset` binary runs, with the process environment injected through
//! [`Inputs`] and the output going to caller-provided writers.
//!
//! `main` parses, calls [`run`], and maps the exit code. A test or an action
//! can call [`run`] with its own [`Inputs`], or [`run_with_context`] with ports
//! it built itself (a different codec, custody, or repository).

pub mod app;
pub mod cli;
pub mod diag;
pub mod input;
pub mod inputs;
pub mod render;
pub mod usage;
pub mod wiring;

pub use app::{run, run_with_context, Ui};
pub use cli::{Cli, Command, ExportFormat, KeyCommand, PersonCommand};
pub use diag::Level;
pub use inputs::{Inputs, Stdin};
