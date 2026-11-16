use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "yzs",
    version,
    about = "Repository secrets: status, keys, recipients, and a runner",
    long_about = None
)]
pub struct Cli {
    /// Repository root; defaults to the current directory and walks up to .sops.yaml
    #[arg(long, global = true, value_name = "DIR")]
    pub repo: Option<PathBuf>,

    /// env | keyring | file:<path> (default: env when YAZEE_AGE_KEY is set, else keyring)
    #[arg(long, global = true, value_name = "KIND")]
    pub custody: Option<String>,

    /// Print the plan and change nothing
    #[arg(long, global = true)]
    pub dry_run: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Readiness report: identity, payloads, coverage, drift, empty values
    Status,
    /// Identity map: label, public key, payload count, whether it is the local key
    Who,
    /// Invariants that need no private key, plus decrypt-verification as admin
    Check,
    /// Run a command with one or more payloads in its environment
    Run {
        /// Payload to load (repeatable); default secrets/prod/infra.env
        #[arg(long = "payload", value_name = "PATH")]
        payload: Vec<String>,
        #[arg(last = true, required = true, value_name = "COMMAND")]
        argv: Vec<String>,
    },
    /// Set one value: paste at a hidden prompt, or --stdin/--from-env
    Set {
        /// Key name in the payload
        key: String,
        #[arg(long = "payload", default_value = "secrets/prod/infra.env")]
        payload: String,
        #[arg(long)]
        stdin: bool,
        #[arg(long = "from-env", value_name = "NAME")]
        from_env: Option<String>,
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
        /// Required to revoke the identity this machine is using
        #[arg(long)]
        force: bool,
    },
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
