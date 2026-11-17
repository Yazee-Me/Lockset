use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "lockset",
    version,
    about = "Repository secrets: status, keys, recipients, and a runner",
    long_about = None,
    after_help = crate::usage::HELP
)]
pub struct Cli {
    /// Repository root; defaults to the current directory and walks up to .sops.yaml
    #[arg(long, global = true, value_name = "DIR")]
    pub repo: Option<PathBuf>,

    /// env | keyring | file:<path> (absolute, mode 0600, outside the repo; default: env when
    /// LOCKSET_AGE_KEY is set, else keyring on a terminal and none otherwise)
    #[arg(long, global = true, value_name = "KIND")]
    pub custody: Option<String>,

    /// Print the plan and change nothing
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Print the plan as JSON instead of text (use with --dry-run)
    #[arg(long, global = true)]
    pub json: bool,

    /// Seconds to wait for another lockset holding the repository lock
    #[arg(long, global = true, value_name = "SECS", default_value_t = 10)]
    pub lock_timeout: u64,

    /// sops binary; overrides LOCKSET_SOPS and the sops on PATH
    #[arg(long, global = true, value_name = "PATH")]
    pub sops: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Readiness report: identity, payloads, coverage, drift, empty values
    Status {
        /// Exit 1 on drift, empty values, a missing identity, or unreadable payloads
        #[arg(long)]
        strict: bool,
    },
    /// Identity map: label, public key, payload count, whether it is the local key
    Who,
    /// Invariants that need no private key, plus decrypt verification for this machine
    Check,
    /// Preflight: repo, sops, custody, identity, coverage, payloads, CI policy
    Doctor,
    /// Print selected payload values for a multi-step pipeline (secret material)
    Export {
        /// Payload to export (repeatable, merged in order, last wins)
        #[arg(long = "payload", value_name = "PATH", required = true)]
        payload: Vec<String>,
        /// dotenv, json, or sh
        #[arg(long, value_enum, default_value_t = ExportFormat::Dotenv)]
        format: ExportFormat,
    },
    /// Run a command with one or more payloads in its environment (identity stripped)
    Run {
        /// Payload to load (repeatable); default secrets/prod/infra.env
        #[arg(long = "payload", value_name = "PATH")]
        payload: Vec<String>,
        /// Hand the child the identity environment; prefer passing an identity file
        #[arg(long = "pass-custody")]
        pass_custody: bool,
        #[arg(last = true, required = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
    /// Set one value: prompt on a terminal, or read --stdin/--from-env/--value-file
    Set {
        /// Key name in the payload
        key: String,
        #[arg(long = "payload", default_value = "secrets/prod/infra.env")]
        payload: String,
        /// Read the value from stdin
        #[arg(long, conflicts_with_all = ["from_env", "value_file"])]
        stdin: bool,
        /// Read the value from this environment variable
        #[arg(long = "from-env", value_name = "NAME")]
        from_env: Option<String>,
        /// Read the value from a file, for mounted secrets
        #[arg(long = "value-file", value_name = "PATH")]
        value_file: Option<PathBuf>,
        /// Store an empty value; empty input is refused without this flag
        #[arg(long = "allow-empty")]
        allow_empty: bool,
    },
    /// Rotate the data key (and re-encrypt every value) of the selected payloads
    Rotate {
        /// Rotate every payload
        #[arg(long)]
        all: bool,
        #[arg(long = "payload", value_name = "PATH")]
        payload: Vec<String>,
    },
    /// Onboarding: grant or revoke a person's key, with the steps they need
    Person {
        #[command(subcommand)]
        command: PersonCommand,
    },
    /// Local identity custody
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
    /// Add a recipient to .sops.yaml and re-wrap the affected payloads
    Grant {
        /// age public key
        public: String,
        #[arg(long, value_name = "NAME")]
        label: String,
        /// Comma-separated payloads (default: every rule)
        #[arg(long, value_name = "PATH,...")]
        only: Option<String>,
    },
    /// Remove a recipient, re-wrap, and rotate the data key
    Revoke {
        /// age public key
        public: Option<String>,
        #[arg(long, value_name = "NAME")]
        label: Option<String>,
        /// Only drop the stanza; keep the current data key
        #[arg(long = "keep-data-key")]
        keep_data_key: bool,
        /// Deliberately decommission this machine by revoking its own identity
        #[arg(long)]
        force: bool,
    },
}

/// The serialization `export` writes to stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ExportFormat {
    Dotenv,
    Json,
    Sh,
}

#[derive(Debug, Subcommand)]
pub enum PersonCommand {
    /// Grant a person's key under a dev-* label
    Add {
        /// age public key
        public: String,
        #[arg(long, value_name = "NAME")]
        label: String,
        /// Comma-separated payloads (default: every rule)
        #[arg(long, value_name = "PATH,...")]
        only: Option<String>,
    },
    /// Revoke a person's key and rotate the data key
    Remove {
        #[arg(long, value_name = "NAME")]
        label: String,
        /// Only drop the stanza; keep the current data key
        #[arg(long = "keep-data-key")]
        keep_data_key: bool,
    },
}

#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Store a private key in custody: paste it, or read --file/--stdin/--from-env
    Import {
        #[arg(long, value_name = "PATH")]
        file: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long = "from-env", value_name = "NAME")]
        from_env: Option<String>,
        /// Replace a different key already in custody
        #[arg(long)]
        force: bool,
    },
    /// What custody holds, and what it can open
    Status,
    /// Remove the key from custody
    Forget {
        #[arg(long)]
        yes: bool,
    },
}
