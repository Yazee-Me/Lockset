//! A mixed sops config outside the repository root: non-age rules parse and
//! are reported per rule, and only a mutation that has to rewrite `age:` on
//! such a rule refuses.

mod common;

use std::path::PathBuf;
use std::process::Output;

use common::{lockset_with, strings, Repo};

const ADMIN: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const NEW: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";

struct Harness {
    repo: Repo,
    shim: PathBuf,
    log: PathBuf,
    secret: String,
}

impl Harness {
    fn new(name: &str) -> Self {
        let repo = Repo::new(name);
        // The sops config is not at the root and the payloads are nested one
        // level below the glob's prefix.
        std::fs::remove_file(repo.sops_path()).unwrap();
        repo.write(
            "sops/settings.yaml",
            &format!(
                "creation_rules:\n- path_regex: conf/age/.*\\.env$\n  age: {ADMIN} # admin\n- path_regex: conf/kms/.*\\.env$\n  kms: arn:aws:kms:eu-west-1:1:key/abc\n"
            ),
        );
        repo.write(
            "conf/age/dev.env",
            &format!(
                "TOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient={ADMIN}\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n"
            ),
        );
        repo.write(
            "conf/kms/infra.env",
            "TOKEN=ENC[a,type:str]\nsops_kms__list_0__map_enc=x\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n",
        );
        repo.write(
            "lockset.toml",
            "[repo]\nsops_config = \"sops/settings.yaml\"\npayload_globs = [\"conf/**/*.env\"]\n",
        );

        let shim = repo.path().join("sops-shim");
        let log = repo.path().join("sops.log");
        std::fs::write(
            &shim,
            concat!(
                "#!/bin/sh\n",
                "printf '%s\\n' \"$*\" >> \"$LOCKSET_SHIM_LOG\"\n",
                "for arg in \"$@\"; do\n",
                "  case \"$arg\" in\n",
                "    --version) echo 'sops 3.13.3'; exit 0 ;;\n",
                "    -d) printf 'TOKEN=v\\n'; exit 0 ;;\n",
                "    updatekeys|rotate) exit 0 ;;\n",
                "  esac\n",
                "done\n",
                "exit 1\n"
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755)).unwrap();

        let secret = lockset_core::SecretKey::generate().expose().to_owned();
        Self {
            repo,
            shim,
            log,
            secret,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        lockset_with(
            &self.repo,
            &strings(args),
            &[
                ("LOCKSET_AGE_KEY", self.secret.as_str()),
                ("LOCKSET_SOPS", self.shim.to_str().unwrap()),
                ("LOCKSET_SHIM_LOG", self.log.to_str().unwrap()),
            ],
            None,
        )
    }

    fn invocations(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.shim);
        let _ = std::fs::remove_file(&self.log);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn a_nested_config_and_globs_discover_both_payloads() {
    let harness = Harness::new("discover");

    let output = harness.run(&["status"]);
    let out = stdout(&output);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(out.contains("conf/age/dev.env"), "{out}");
    assert!(out.contains("conf/kms/infra.env"), "{out}");
}

#[test]
fn each_non_age_rule_is_reported_on_its_own_line() {
    let harness = Harness::new("reported");

    let output = harness.run(&["check"]);
    let out = stdout(&output);

    let line = out
        .lines()
        .find(|line| line.starts_with("rule 2:") && line.contains("conf/kms"))
        .unwrap_or_else(|| panic!("no per-rule report: {out}"));
    assert!(line.contains("no age recipients (kms)"), "{line}");
    assert!(line.contains("grant and revoke refuse"), "{line}");
    assert!(
        !out.lines().any(|line| line.starts_with("rule 1:")),
        "the age rule needs no warning: {out}"
    );
}

#[test]
fn grant_refuses_a_kms_rule_with_a_scoped_message() {
    let harness = Harness::new("refuse");

    let output = harness.run(&["grant", NEW, "--label", "dev-new"]);
    let err = stderr(&output);

    assert_eq!(output.status.code(), Some(2), "{err}");
    assert!(err.contains("conf/kms/.*"), "{err}");
    assert!(err.contains("no age recipients (kms)"), "{err}");
    assert!(err.contains("--only"), "{err}");
    // Nothing reached sops: the refusal is before the plan.
    assert_eq!(harness.invocations(), "");

    let settings = harness.repo.read("sops/settings.yaml");
    assert!(!settings.contains(NEW), "{settings}");
}

#[test]
fn grant_targets_only_the_age_rule_and_passes_the_config_to_sops() {
    let harness = Harness::new("mutate");

    let output = harness.run(&[
        "grant",
        NEW,
        "--label",
        "dev-new",
        "--only",
        "conf/age/dev.env",
    ]);
    let err = stderr(&output);

    assert_eq!(output.status.code(), Some(0), "{err}");

    let settings = harness.repo.read("sops/settings.yaml");
    assert!(settings.contains(NEW), "{settings}");
    assert!(
        settings.contains("  kms: arn:aws:kms:eu-west-1:1:key/abc\n"),
        "the KMS rule must be byte-identical: {settings}"
    );
    assert!(settings.contains("# admin,dev-new"), "{settings}");

    let calls = harness.invocations();
    assert!(
        calls
            .lines()
            .any(|line| line.starts_with("--config sops/settings.yaml ")
                && line.contains("updatekeys")),
        "sops must be told where the config is: {calls}"
    );
    // The throwaway root `.sops.yaml` must not reappear.
    assert!(!harness.repo.path().join(".sops.yaml").exists());
}

#[test]
fn rotate_plans_for_a_mixed_repository() {
    let harness = Harness::new("rotate");

    let output = harness.run(&["--dry-run", "rotate", "--all"]);
    let out = stdout(&output);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(out.contains("would rotate"), "{out}");
    assert!(out.contains("conf/kms/infra.env"), "{out}");
}
