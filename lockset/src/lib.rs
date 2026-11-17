//! Lockset's orchestration as a library: the same command handlers the
//! `lockset` binary runs, with the process environment injected through
//! [`Inputs`] and the output going to caller-provided writers.
//!
//! `main` parses, calls [`run`], and maps the exit code. A test or an action
//! can call [`run`] with its own [`Inputs`], or [`run_with_context`] with ports
//! it built itself (a different codec, custody, or repository).
//!
//! # Example
//!
//! ```
//! use clap::Parser;
//! use lockset::{run, Cli, Inputs};
//!
//! let dir = std::env::temp_dir().join(format!("lockset-doc-{}", std::process::id()));
//! std::fs::create_dir_all(&dir).unwrap();
//! std::fs::write(
//!     dir.join(".sops.yaml"),
//!     "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x\n",
//! )
//! .unwrap();
//!
//! let cli = Cli::parse_from(["lockset", "--repo", dir.to_str().unwrap(), "status"]);
//! let inputs = Inputs::default();
//! let mut out = Vec::new();
//! let mut err = Vec::new();
//! let code = run(cli, &inputs, &mut out, &mut err);
//!
//! assert_eq!(code, 0, "{}", String::from_utf8_lossy(&err));
//! assert!(String::from_utf8_lossy(&out).contains("identity: none"));
//! std::fs::remove_dir_all(&dir).ok();
//! ```

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
