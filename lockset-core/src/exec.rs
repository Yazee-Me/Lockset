use std::collections::BTreeMap;

use crate::model::{PathId, SecretKey};
use crate::plan::{Change, Plan};
use crate::ports::{Codec, Custody, Repo};
use crate::{Error, Result};

/// Execute a plan through ports. The only place mutations happen; `--dry-run`
/// simply never calls this.
///
/// The apply is transactional: the bytes of every file the plan touches are
/// read before the first write, and a failure restores them, so a command
/// either lands completely or leaves the repository as it was. A failure to
/// restore is an [`Error::Partial`] naming the files and the recovery step, so
/// a half-applied mutation can never look like success.
///
/// `.sops.yaml` is written before the payloads that re-wrap against it, because
/// sops `updatekeys` reads the map: a map that trails the payloads would re-wrap
/// them to the old recipient set. The rollback, not the order, is what makes
/// the apply all-or-nothing.
pub fn apply(
    plan: &Plan,
    repo: &dyn Repo,
    codec: &dyn Codec,
    custody: &dyn Custody,
    key: &SecretKey,
) -> Result<Vec<String>> {
    one_domain(plan)?;
    let backups = backup(plan, repo)?;
    check_inputs(plan, &backups)?;
    let mut log = Vec::new();
    let mut written: Vec<PathId> = Vec::new();
    for change in &plan.changes {
        match run(change, repo, codec, custody, key) {
            Ok(line) => {
                if let Some(path) = change.path() {
                    written.push(path.clone());
                }
                log.push(line);
            }
            Err(cause) => return Err(undo(repo, &backups, &written, change, cause)),
        }
    }
    Ok(log)
}

/// A plan must not mix repository and custody changes: files can be restored,
/// a stored or forgotten key cannot.
fn one_domain(plan: &Plan) -> Result<()> {
    let files = plan.changes.iter().any(|change| change.path().is_some());
    let custody = plan.changes.iter().any(|change| change.path().is_none());
    if files && custody {
        return Err(Error::failed(
            "a plan cannot mix repository and custody changes; apply them separately",
        ));
    }
    Ok(())
}

/// Read every file the plan touches before touching any of them.
fn backup(plan: &Plan, repo: &dyn Repo) -> Result<BTreeMap<PathId, Vec<u8>>> {
    let mut backups = BTreeMap::new();
    for change in &plan.changes {
        let Some(path) = change.path() else {
            continue;
        };
        if backups.contains_key(path) {
            continue;
        }
        let bytes = repo.read(path).map_err(|error| {
            Error::failed(format!("cannot back up {path} before changing it: {error}"))
        })?;
        backups.insert(path.clone(), bytes);
    }
    Ok(backups)
}

/// Refuse to write when a file the plan was built from changed in between: the
/// snapshot and the apply must describe the same inputs.
fn check_inputs(plan: &Plan, backups: &BTreeMap<PathId, Vec<u8>>) -> Result<()> {
    for change in &plan.changes {
        let Some(path) = change.path() else {
            continue;
        };
        let Some(expected) = plan.expected.get(path) else {
            return Err(Error::failed(format!(
                "the plan was built without a digest of {path}; refusing to write"
            )));
        };
        let bytes = backups
            .get(path)
            .ok_or_else(|| Error::failed(format!("no backup of {path}")))?;
        if crate::digest(bytes) != *expected {
            return Err(Error::conflict(format!(
                "{path} changed after the snapshot was taken; nothing was written, re-run the command"
            )));
        }
    }
    Ok(())
}

fn run(
    change: &Change,
    repo: &dyn Repo,
    codec: &dyn Codec,
    custody: &dyn Custody,
    key: &SecretKey,
) -> Result<String> {
    Ok(match change {
        Change::WriteFile { path, contents } => {
            repo.write(path, contents.as_bytes())?;
            format!("wrote {path}")
        }
        Change::UpdateKeys { payload } => {
            codec.rewrap(payload, key)?;
            format!("re-wrapped {payload}")
        }
        Change::RotateDataKey { payload } => {
            codec.rekey(payload, key)?;
            format!("rotated data key: {payload}")
        }
        Change::SetValue {
            payload,
            name,
            value,
        } => {
            codec.set_value(payload, name, value.expose(), key)?;
            format!("set {name} in {payload}")
        }
        Change::StoreKey { custody: kind } => {
            custody.set(key)?;
            format!("stored the key in {kind}")
        }
        Change::ForgetKey { custody: kind } => {
            custody.forget()?;
            format!("removed the key from {kind}")
        }
    })
}

/// Restore what this apply changed, newest first, including the change that
/// failed. A failed restore is a partial apply: it names the files to recover
/// and never returns `Ok`.
fn undo(
    repo: &dyn Repo,
    backups: &BTreeMap<PathId, Vec<u8>>,
    written: &[PathId],
    failed: &Change,
    cause: Error,
) -> Error {
    let mut paths: Vec<&PathId> = Vec::new();
    for path in written {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    if let Some(path) = failed.path() {
        if !paths.contains(&path) {
            paths.push(path);
        }
    }
    let mut unrestored = Vec::new();
    for path in paths.iter().rev() {
        let Some(bytes) = backups.get(*path) else {
            continue;
        };
        if let Err(error) = repo.write(path, bytes) {
            unrestored.push(format!("{path} ({error})"));
        }
    }
    if unrestored.is_empty() {
        let message = format!("{cause}; nothing was changed (the repository was restored)");
        // The rollback succeeded, so the failure keeps its class: an external
        // tool still exits 4 and a custody error 3, not the generic 1.
        return match cause {
            Error::Tool(_) => Error::tool(message),
            _ => Error::failed(message),
        };
    }
    Error::partial(format!(
        "{cause}; the mutation stopped part-way and could not restore {}; recover those \
         files from version control (`git checkout -- <path>`) and check `lockset status`",
        unrestored.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use zeroize::Zeroizing;

    use super::*;
    use crate::model::CustodyKind;
    use crate::plan::SecretValue;

    /// In-memory repository: payloads live in a map and writes can be made to
    /// fail once or always, so a rollback can be exercised on its own.
    struct MemoryRepo {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
        writes: RefCell<Vec<String>>,
        fail_once: RefCell<Vec<String>>,
        fail_always: RefCell<Vec<String>>,
    }

    impl MemoryRepo {
        fn new(files: &[(&str, &str)]) -> Self {
            Self {
                files: RefCell::new(
                    files
                        .iter()
                        .map(|(path, text)| ((*path).to_owned(), text.as_bytes().to_vec()))
                        .collect(),
                ),
                writes: RefCell::new(Vec::new()),
                fail_once: RefCell::new(Vec::new()),
                fail_always: RefCell::new(Vec::new()),
            }
        }

        fn fail_once(&self, path: &str) {
            self.fail_once.borrow_mut().push(path.to_owned());
        }

        fn fail_always(&self, path: &str) {
            self.fail_always.borrow_mut().push(path.to_owned());
        }

        fn text(&self, path: &str) -> String {
            String::from_utf8(self.files.borrow()[path].clone()).unwrap()
        }

        fn put(&self, path: &PathId, text: &str) {
            self.files
                .borrow_mut()
                .insert(path.as_str().to_owned(), text.as_bytes().to_vec());
        }
    }

    impl Repo for MemoryRepo {
        fn list(&self, _prefix: &PathId) -> Result<Vec<PathId>> {
            Ok(Vec::new())
        }

        fn read(&self, id: &PathId) -> Result<Vec<u8>> {
            self.files
                .borrow()
                .get(id.as_str())
                .cloned()
                .ok_or_else(|| Error::failed(format!("no such file {id}")))
        }

        fn write(&self, id: &PathId, bytes: &[u8]) -> Result<()> {
            if self
                .fail_always
                .borrow()
                .iter()
                .any(|path| path == id.as_str())
            {
                return Err(Error::failed(format!("cannot write {id}")));
            }
            let mut once = self.fail_once.borrow_mut();
            if let Some(index) = once.iter().position(|path| path == id.as_str()) {
                once.remove(index);
                return Err(Error::failed(format!("cannot write {id}")));
            }
            drop(once);
            self.files
                .borrow_mut()
                .insert(id.as_str().to_owned(), bytes.to_vec());
            self.writes.borrow_mut().push(id.as_str().to_owned());
            Ok(())
        }
    }

    /// A codec that rewrites the payload in place and can fail a chosen call.
    struct MemoryCodec<'a> {
        repo: &'a MemoryRepo,
        calls: RefCell<usize>,
        fail_on_call: RefCell<Option<usize>>,
        /// Report the failure as the external tool, as sops would.
        tool_failure: bool,
    }

    impl<'a> MemoryCodec<'a> {
        fn new(repo: &'a MemoryRepo) -> Self {
            Self {
                repo,
                calls: RefCell::new(0),
                fail_on_call: RefCell::new(None),
                tool_failure: false,
            }
        }

        fn fail_on_call(&self, call: usize) {
            *self.fail_on_call.borrow_mut() = Some(call);
        }

        fn call(&self, what: &str, id: &PathId, written: &str) -> Result<()> {
            let mut calls = self.calls.borrow_mut();
            *calls += 1;
            if *self.fail_on_call.borrow() == Some(*calls) {
                let message = format!("sops {what} {id} failed");
                return Err(if self.tool_failure {
                    Error::tool(message)
                } else {
                    Error::failed(message)
                });
            }
            drop(calls);
            self.repo.put(id, written);
            Ok(())
        }
    }

    impl Codec for MemoryCodec<'_> {
        fn decrypt(&self, _id: &PathId, _key: &SecretKey) -> Result<Vec<u8>> {
            Ok(Vec::new())
        }

        fn rewrap(&self, id: &PathId, _key: &SecretKey) -> Result<()> {
            self.call("rewrap", id, "rewrapped")
        }

        fn rekey(&self, id: &PathId, _key: &SecretKey) -> Result<()> {
            self.call("rekey", id, "rekeyed")
        }

        fn set_value(&self, id: &PathId, name: &str, _value: &str, _key: &SecretKey) -> Result<()> {
            self.call("set", id, name)
        }
    }

    #[derive(Default)]
    struct MemoryCustody {
        stored: RefCell<bool>,
        fail_set: bool,
    }

    impl Custody for MemoryCustody {
        fn get(&self) -> Result<Option<SecretKey>> {
            Ok(None)
        }

        fn set(&self, _key: &SecretKey) -> Result<()> {
            if self.fail_set {
                return Err(Error::failed("keychain refused"));
            }
            *self.stored.borrow_mut() = true;
            Ok(())
        }

        fn forget(&self) -> Result<()> {
            *self.stored.borrow_mut() = false;
            Ok(())
        }

        fn kind(&self) -> CustodyKind {
            CustodyKind::Memory
        }
    }

    fn plan() -> Plan {
        let mut plan = Plan::default();
        plan.push(Change::WriteFile {
            path: PathId::parse(".sops.yaml").unwrap(),
            contents: "new map\n".to_owned(),
        });
        plan.push(Change::UpdateKeys {
            payload: PathId::parse("secrets/a.env").unwrap(),
        });
        plan.push(Change::RotateDataKey {
            payload: PathId::parse("secrets/a.env").unwrap(),
        });
        plan.push(Change::SetValue {
            payload: PathId::parse("secrets/b.env").unwrap(),
            name: "K".to_owned(),
            value: SecretValue::new(Zeroizing::new("v".to_owned())),
        });
        plan
    }

    /// Seal a plan with the digests the fake repository currently holds, as
    /// wiring does from a snapshot.
    fn seal(plan: &mut Plan, repo: &MemoryRepo) {
        let mut digests = BTreeMap::new();
        for path in plan.changes.iter().filter_map(Change::path) {
            if let Ok(bytes) = repo.read(path) {
                digests.insert(path.clone(), crate::digest(&bytes));
            }
        }
        plan.expect(&digests);
    }

    fn sealed(repo: &MemoryRepo) -> Plan {
        let mut plan = plan();
        seal(&mut plan, repo);
        plan
    }

    fn repo() -> MemoryRepo {
        MemoryRepo::new(&[
            (".sops.yaml", "old map\n"),
            ("secrets/a.env", "A"),
            ("secrets/b.env", "B"),
        ])
    }

    fn assert_untouched(repo: &MemoryRepo) {
        assert_eq!(repo.text(".sops.yaml"), "old map\n");
        assert_eq!(repo.text("secrets/a.env"), "A");
        assert_eq!(repo.text("secrets/b.env"), "B");
    }

    #[test]
    fn a_successful_apply_reports_every_step() {
        let repo = repo();
        let codec = MemoryCodec::new(&repo);
        let custody = MemoryCustody::default();
        let key = SecretKey::generate();

        let log = apply(&sealed(&repo), &repo, &codec, &custody, &key).unwrap();

        assert_eq!(
            log,
            [
                "wrote .sops.yaml",
                "re-wrapped secrets/a.env",
                "rotated data key: secrets/a.env",
                "set K in secrets/b.env",
            ]
        );
        assert_eq!(repo.text(".sops.yaml"), "new map\n");
        assert_eq!(repo.text("secrets/a.env"), "rekeyed");
        assert_eq!(repo.text("secrets/b.env"), "K");
        assert_eq!(repo.writes.borrow().as_slice(), [".sops.yaml"]);
    }

    #[test]
    fn a_failed_step_restores_every_file() {
        for step in 1..=3 {
            let repo = repo();
            let codec = MemoryCodec::new(&repo);
            codec.fail_on_call(step);
            let custody = MemoryCustody::default();
            let key = SecretKey::generate();

            let error = apply(&sealed(&repo), &repo, &codec, &custody, &key).unwrap_err();

            assert!(matches!(error, Error::Failed(_)), "step {step}: {error:?}");
            assert!(
                error.to_string().contains("the repository was restored"),
                "step {step}: {error}"
            );
            assert_untouched(&repo);
        }
    }

    #[test]
    fn a_tool_failure_keeps_its_class_after_a_clean_rollback() {
        let repo = repo();
        let mut codec = MemoryCodec::new(&repo);
        codec.tool_failure = true;
        codec.fail_on_call(2);
        let custody = MemoryCustody::default();
        let key = SecretKey::generate();

        let error = apply(&sealed(&repo), &repo, &codec, &custody, &key).unwrap_err();

        assert!(matches!(error, Error::Tool(_)), "{error:?}");
        assert!(
            error.to_string().contains("the repository was restored"),
            "{error}"
        );
        assert_untouched(&repo);
    }

    #[test]
    fn a_failed_map_write_restores_the_payloads() {
        let repo = repo();
        repo.fail_once(".sops.yaml");
        let codec = MemoryCodec::new(&repo);
        let custody = MemoryCustody::default();
        let key = SecretKey::generate();

        let error = apply(&sealed(&repo), &repo, &codec, &custody, &key).unwrap_err();

        assert!(matches!(error, Error::Failed(_)), "{error:?}");
        assert_untouched(&repo);
    }

    #[test]
    fn a_failed_restore_is_a_partial_apply_that_names_the_file() {
        let repo = repo();
        repo.fail_always("secrets/a.env");
        let codec = MemoryCodec::new(&repo);
        codec.fail_on_call(2);
        let custody = MemoryCustody::default();
        let key = SecretKey::generate();

        let error = apply(&sealed(&repo), &repo, &codec, &custody, &key).unwrap_err();

        assert!(matches!(error, Error::Partial(_)), "{error:?}");
        let message = error.to_string();
        assert!(message.contains("secrets/a.env"), "{message}");
        assert!(message.contains("git checkout"), "{message}");
    }

    #[test]
    fn a_plan_that_touches_an_unreadable_file_changes_nothing() {
        let repo = repo();
        let codec = MemoryCodec::new(&repo);
        let custody = MemoryCustody::default();
        let key = SecretKey::generate();
        let mut plan = plan();
        plan.push(Change::UpdateKeys {
            payload: PathId::parse("secrets/missing.env").unwrap(),
        });
        seal(&mut plan, &repo);

        let error = apply(&plan, &repo, &codec, &custody, &key).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("cannot back up secrets/missing.env"),
            "{error}"
        );
        assert!(repo.writes.borrow().is_empty());
        assert_untouched(&repo);
    }

    #[test]
    fn a_plan_cannot_mix_custody_and_file_changes() {
        let repo = repo();
        let codec = MemoryCodec::new(&repo);
        let custody = MemoryCustody::default();
        let key = SecretKey::generate();
        let mut mixed = sealed(&repo);
        mixed.push(Change::StoreKey {
            custody: CustodyKind::Memory,
        });

        let error = apply(&mixed, &repo, &codec, &custody, &key).unwrap_err();

        assert!(error.to_string().contains("cannot mix"), "{error}");
        assert!(repo.writes.borrow().is_empty());
        assert!(!*custody.stored.borrow());
    }

    #[test]
    fn a_changed_input_aborts_before_writing() {
        let repo = repo();
        let codec = MemoryCodec::new(&repo);
        let custody = MemoryCustody::default();
        let key = SecretKey::generate();
        let plan = sealed(&repo);

        // Another process (or an editor) rewrites the map before the apply.
        repo.put(&PathId::parse(".sops.yaml").unwrap(), "edited elsewhere\n");

        let error = apply(&plan, &repo, &codec, &custody, &key).unwrap_err();

        assert!(matches!(error, Error::Conflict(_)), "{error:?}");
        assert!(error.to_string().contains(".sops.yaml changed"), "{error}");
        assert!(repo.writes.borrow().is_empty(), "nothing may be written");
        assert_eq!(repo.text(".sops.yaml"), "edited elsewhere\n");
        assert_eq!(repo.text("secrets/a.env"), "A");
    }

    #[test]
    fn a_plan_without_digests_is_refused() {
        let repo = repo();
        let codec = MemoryCodec::new(&repo);
        let custody = MemoryCustody::default();
        let key = SecretKey::generate();

        let error = apply(&plan(), &repo, &codec, &custody, &key).unwrap_err();

        assert!(error.to_string().contains("without a digest"), "{error}");
        assert!(repo.writes.borrow().is_empty());
    }

    #[test]
    fn a_failed_custody_change_is_reported() {
        let repo = repo();
        let codec = MemoryCodec::new(&repo);
        let custody = MemoryCustody {
            stored: RefCell::new(false),
            fail_set: true,
        };
        let key = SecretKey::generate();
        let mut store = Plan::default();
        store.push(Change::StoreKey {
            custody: CustodyKind::Memory,
        });

        let error = apply(&store, &repo, &codec, &custody, &key).unwrap_err();

        assert!(matches!(error, Error::Failed(_)), "{error:?}");
        assert!(error.to_string().contains("keychain refused"), "{error}");
        assert!(repo.writes.borrow().is_empty());
    }
}
