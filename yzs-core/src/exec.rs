use crate::model::SecretKey;
use crate::plan::{Change, Plan};
use crate::ports::{Codec, Custody, Repo};
use crate::Result;

/// Execute a plan through ports. The only place mutations happen; `--dry-run`
/// simply never calls this.
pub fn apply(
    plan: &Plan,
    repo: &dyn Repo,
    codec: &dyn Codec,
    custody: &dyn Custody,
    key: &SecretKey,
) -> Result<Vec<String>> {
    let mut log = Vec::new();
    for change in &plan.changes {
        match change {
            Change::WriteFile { path, contents } => {
                repo.write(path, contents.as_bytes())?;
                log.push(format!("wrote {path}"));
            }
            Change::UpdateKeys { payload } => {
                codec.rewrap(payload, key)?;
                log.push(format!("re-wrapped {payload}"));
            }
            Change::RotateDataKey { payload } => {
                codec.rekey(payload, key)?;
                log.push(format!("rotated data key: {payload}"));
            }
            Change::SetValue {
                payload,
                name,
                value,
            } => {
                codec.set_value(payload, name, value, key)?;
                log.push(format!("set {name} in {payload}"));
            }
            Change::StoreKey { custody: kind } => {
                custody.set(key)?;
                log.push(format!("stored the key in {kind}"));
            }
            Change::ForgetKey { custody: kind } => {
                custody.forget()?;
                log.push(format!("removed the key from {kind}"));
            }
        }
    }
    Ok(log)
}
