//! The binary: parse the arguments, capture the process inputs, call the
//! library, and turn its exit code into the process's.

use std::process::ExitCode;

use clap::Parser;
use lockset::{run, Cli, Inputs};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let inputs = Inputs::capture();
    let mut out = std::io::stdout();
    let mut err = std::io::stderr();
    ExitCode::from(run(cli, &inputs, &mut out, &mut err))
}
