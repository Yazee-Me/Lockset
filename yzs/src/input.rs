use std::io::{IsTerminal, Read};
use std::path::Path;

use anyhow::{bail, Context, Result};
use yzs_core::SecretKey;
use zeroize::Zeroizing;

/// A dotenv value: hidden prompt by default, or stdin, or an environment
/// variable. Trailing newlines are dropped; embedded lines are refused.
pub fn read_value(stdin_flag: bool, from_env: Option<&str>) -> Result<Zeroizing<String>> {
    let raw = if let Some(name) = from_env {
        std::env::var(name).with_context(|| format!("{name} is not set"))?
    } else if stdin_flag || !std::io::stdin().is_terminal() {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .context("cannot read stdin")?;
        buffer
    } else {
        rpassword::prompt_password("value (input hidden): ").context("cannot read the value")?
    };
    let value = raw.trim_end_matches(['\r', '\n']).to_owned();
    if value.contains(['\r', '\n']) {
        bail!("a dotenv value must be a single line");
    }
    Ok(Zeroizing::new(value))
}

/// Read a private key without it ever reaching argv or shell history.
pub fn read_key(
    file: Option<&Path>,
    stdin_flag: bool,
    from_env: Option<&str>,
) -> Result<SecretKey> {
    let text = if let Some(path) = file {
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?
    } else if let Some(name) = from_env {
        std::env::var(name).with_context(|| format!("{name} is not set"))?
    } else if stdin_flag || !std::io::stdin().is_terminal() {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .context("cannot read stdin")?;
        buffer
    } else {
        rpassword::prompt_password("paste the age private key (input hidden): ")
            .context("cannot read the pasted key")?
    };

    SecretKey::from_text(&text).map_err(Into::into)
}

pub fn confirm(question: &str) -> Result<bool> {
    use std::io::Write;
    print!("{question} [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin().read_line(&mut answer)?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}
