//! The identity registry in `lockset.toml`: labels from config, comments as a
//! migration input, and drift reported instead of silently repaired.

#![cfg(unix)]
mod common;

use std::path::PathBuf;
use std::process::Output;

use common::{lockset_with, strings, Repo};

const ADMIN: &str = "age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x";
const ALICE: &str = "age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q";
const CAROL: &str = "age1y4gs9hk93n3mpvhwydaq7uz4mn3a0esf0wfh3md2v2qz4hye9frsfpelwh";
const DAVE: &str = "age10fa50c9n9te2qhh6lvsjuwxzprmk5wwtnwz3a2s0z65xg3nw2yes87mc0g";

struct Harness {
    repo: Repo,
    shim: PathBuf,
    secret: String,
}

impl Harness {
    /// A repository whose map names ADMIN and ALICE, without comments.
    fn new(name: &str) -> Self {
        let repo = Repo::new(name);
        Self::with_map(
            repo,
            &format!(
                "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{ALICE}\n"
            ),
            "TOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient=age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x\nsops_age__list_1__map_enc=x\nsops_age__list_1__map_recipient=age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n",
        )
    }

    fn with_map(repo: Repo, map: &str, payload: &str) -> Self {
        repo.write(".sops.yaml", map);
        repo.write("secrets/dev.env", payload);
        let shim = repo.path().join("sops-shim");
        std::fs::write(
            &shim,
            concat!(
                "#!/bin/sh\n",
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
        Self { repo, shim, secret }
    }

    fn config(&self, text: &str) {
        self.repo.write("lockset.toml", text);
    }

    fn registry(&self, identities: &[(&str, &str, &[&str])]) {
        let mut text = String::new();
        for (label, key, roles) in identities {
            text.push_str(&format!(
                "\n[[identities]]\nlabel = \"{label}\"\npublic = \"{key}\"\n"
            ));
            if !roles.is_empty() {
                let roles: Vec<String> = roles.iter().map(|role| format!("\"{role}\"")).collect();
                text.push_str(&format!("roles = [{}]\n", roles.join(", ")));
            }
        }
        self.config(&text);
    }

    /// Emulate sops on `updatekeys`: append `key` to the payload, so the
    /// metadata matches the map after a grant instead of lagging behind it.
    fn shim_adds_on_updatekeys(&self, key: &str) {
        std::fs::write(
            &self.shim,
            concat!(
                "#!/bin/sh\n",
                "for arg in \"$@\"; do\n",
                "  case \"$arg\" in\n",
                "    --version) echo 'sops 3.13.3'; exit 0 ;;\n",
                "    -d) printf 'TOKEN=v\\n'; exit 0 ;;\n",
                "    updatekeys)\n",
                "      printf 'sops_age__list_2__map_enc=x\\nsops_age__list_2__map_recipient=%s\\n' '$KEY' >> \"$3\"\n",
                "      exit 0 ;;\n",
                "    rotate) exit 0 ;;\n",
                "  esac\n",
                "done\n",
                "exit 1\n"
            )
            .replace("$KEY", key),
        )
        .unwrap();
    }

    fn run(&self, args: &[&str]) -> Output {
        lockset_with(
            &self.repo,
            &strings(args),
            &[
                ("LOCKSET_AGE_KEY", self.secret.as_str()),
                ("LOCKSET_SOPS", self.shim.to_str().unwrap()),
            ],
            None,
        )
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.shim);
    }
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn who_lists_the_config_registry_without_comments() {
    let harness = Harness::new("who-config");
    harness.registry(&[("admin", ADMIN, &["admin"]), ("dev-alice", ALICE, &[])]);

    let output = harness.run(&["who"]);
    let out = stdout(&output);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(out.contains("admin"), "{out}");
    assert!(out.contains(ADMIN), "{out}");
    assert!(out.contains("dev-alice"), "{out}");
    assert!(out.contains(ALICE), "{out}");
}

#[test]
fn revoke_by_label_works_from_the_registry_alone() {
    let harness = Harness::new("revoke-label");
    harness.registry(&[("admin", ADMIN, &["admin"]), ("dev-alice", ALICE, &[])]);

    let output = harness.run(&[
        "revoke",
        "--label",
        "dev-alice",
        "--keep-data-key",
        "--dry-run",
    ]);
    let out = stdout(&output);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(!out.is_empty(), "a plan is printed: {out}");
}

#[test]
fn a_registered_grant_writes_no_comment_and_keeps_the_label() {
    let harness = Harness::new("grant-registered");
    harness.registry(&[("admin", ADMIN, &["admin"]), ("dev-carol", CAROL, &[])]);

    let registered = harness.run(&[
        "grant",
        CAROL,
        "--label",
        "dev-carol",
        "--only",
        "secrets/dev.env",
        "--dry-run",
    ]);
    assert_eq!(registered.status.code(), Some(0), "{}", stderr(&registered));

    // The real grant lands with no comment at all: the registry carries the
    // label, the map carries only keys.
    let applied = harness.run(&[
        "grant",
        CAROL,
        "--label",
        "dev-carol",
        "--only",
        "secrets/dev.env",
    ]);
    assert_eq!(applied.status.code(), Some(0), "{}", stderr(&applied));
    let map = harness.repo.read(".sops.yaml");
    assert!(map.contains(CAROL), "{map}");
    assert!(!map.contains('#'), "no comment is written: {map}");
    assert!(!map.contains("dev-carol"), "{map}");

    let wrong_label = harness.run(&[
        "grant",
        CAROL,
        "--label",
        "dev-dave",
        "--only",
        "secrets/dev.env",
        "--dry-run",
    ]);
    let err = stderr(&wrong_label);
    assert_eq!(wrong_label.status.code(), Some(2), "{err}");
    assert!(err.contains("registered as dev-carol"), "{err}");
}

#[test]
fn grant_registers_an_unregistered_identity_in_lockset_toml() {
    let harness = Harness::new("grant-registers");
    harness.registry(&[("admin", ADMIN, &["admin"])]);
    harness.shim_adds_on_updatekeys(CAROL);

    let output = harness.run(&["grant", CAROL, "--label", "dev-carol"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let config = harness.repo.read("lockset.toml");
    assert_eq!(config.matches("[[identities]]").count(), 2, "{config}");
    assert!(config.contains("label = \"dev-carol\""), "{config}");
    assert!(
        config.contains(&format!("public = \"{CAROL}\"")),
        "{config}"
    );
    assert!(
        config.contains(&format!("public = \"{ADMIN}\"")),
        "the existing entry stays: {config}"
    );
    assert!(
        !config.contains("roles = []"),
        "no empty roles array: {config}"
    );

    let map = harness.repo.read(".sops.yaml");
    assert!(map.contains(CAROL), "{map}");
    assert!(!map.contains("dev-carol"), "no comment is written: {map}");

    let status = harness.run(&["status", "--json"]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    let json: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(json["drift"], serde_json::json!([]), "{json}");

    // Other checks can fail for a throwaway key, so assert the drift line only.
    let checked = harness.run(&["check"]);
    let out = stdout(&checked);
    let line = out
        .lines()
        .find(|line| line.contains("labels and recipients agree"))
        .unwrap_or_else(|| panic!("no drift check in: {out}"));
    assert!(line.contains("ok"), "{line}");
}

#[test]
fn revoke_removes_the_registry_entry_and_the_recipient() {
    let repo = Repo::new("revoke-registers");
    let harness = Harness::with_map(
        repo,
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{ALICE},{CAROL}\n"
        ),
        "TOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient=age1p243ylp98pr939vj8eqsmaczq8c9gwxwnlupz9pvelpfj6ha0cgqjsue6x\nsops_age__list_1__map_enc=x\nsops_age__list_1__map_recipient=age1vvq9jvcxj0xw2jl4x0az4ndvg7ew39c2pge0u8scdpwejlyazyjqqcs64q\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n",
    );
    harness.registry(&[
        ("admin", ADMIN, &["admin"]),
        ("dev-alice", ALICE, &[]),
        ("dev-carol", CAROL, &[]),
    ]);

    let output = harness.run(&["revoke", "--label", "dev-carol", "--keep-data-key"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let config = harness.repo.read("lockset.toml");
    assert!(!config.contains(CAROL), "{config}");
    assert!(config.contains("dev-alice"), "{config}");
    assert!(config.contains("roles = [\"admin\"]"), "{config}");

    let map = harness.repo.read(".sops.yaml");
    assert!(!map.contains(CAROL), "{map}");
    assert!(map.contains(ALICE), "{map}");

    let status = harness.run(&["status", "--json"]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    let json: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(json["drift"], serde_json::json!([]), "{json}");
}

#[test]
fn grant_leaves_a_rule_with_no_recipients_byte_identical() {
    let harness = Harness::with_map(
        Repo::new("bare-rule"),
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{ALICE}\n  - path_regex: bare/.*\\.env$\n"
        ),
        "TOKEN=ENC[a,type:str]\n",
    );

    let output = harness.run(&["grant", DAVE, "--label", "dev-dave"]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let map = harness.repo.read(".sops.yaml");
    assert!(map.contains(DAVE), "{map}");
    assert!(
        map.ends_with("  - path_regex: bare/.*\\.env$\n"),
        "the empty rule stays byte-identical: {map}"
    );
    assert!(
        !map.contains("bare/.*\\.env$\n    age:"),
        "no age line is added: {map}"
    );
}

#[test]
fn a_config_outside_the_repository_reports_but_cannot_register() {
    let harness = Harness::new("config-outside");
    let outside = harness
        .repo
        .path()
        .with_file_name(format!("outside-{}.toml", std::process::id()));
    std::fs::write(
        &outside,
        format!("[[identities]]\nlabel = \"admin\"\npublic = \"{ADMIN}\"\n"),
    )
    .unwrap();
    let config = outside.to_str().unwrap();

    // A read-only command keeps working: the report never needs a rewrite.
    let status = harness.run(&["--config", config, "status", "--json"]);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    let json: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(json["identities"][0]["label"], "admin");

    // A registry edit refuses with exit 2 and says why.
    let grant = harness.run(&["--config", config, "grant", CAROL, "--label", "dev-carol"]);
    let err = stderr(&grant);
    assert_eq!(grant.status.code(), Some(2), "{err}");
    assert!(err.contains("no editable config document"), "{err}");

    let _ = std::fs::remove_file(&outside);
}

#[test]
fn an_unknown_label_is_refused_for_revoke() {
    let harness = Harness::new("revoke-unknown");
    harness.registry(&[("admin", ADMIN, &["admin"])]);

    let output = harness.run(&["revoke", "--label", "nobody", "--dry-run"]);
    let err = stderr(&output);

    assert_eq!(output.status.code(), Some(2), "{err}");
    assert!(err.contains("no identity labelled nobody"), "{err}");
}

#[test]
fn the_migration_fragment_round_trips_the_comments() {
    let harness = Harness::with_map(
        Repo::new("migration"),
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{ALICE} # admin,dev-alice\n"
        ),
        "TOKEN=ENC[a,type:str]\n",
    );
    let map_before = harness.repo.read(".sops.yaml");

    let before = harness.run(&["who"]);
    let fragment = harness.run(&["who", "--toml"]);
    let text = stdout(&fragment);
    assert_eq!(fragment.status.code(), Some(0), "{}", stderr(&fragment));
    assert_eq!(text.matches("[[identities]]").count(), 2, "{text}");
    assert!(text.contains("label = \"admin\""), "{text}");
    assert!(text.contains(&format!("public = \"{ALICE}\"")), "{text}");

    harness.config(&text);
    let after = harness.run(&["who"]);

    assert_eq!(
        stdout(&before),
        stdout(&after),
        "the labels must survive the migration"
    );
    assert_eq!(
        harness.repo.read(".sops.yaml"),
        map_before,
        "migration must not touch recipients"
    );
}

#[test]
fn a_free_text_comment_survives_a_grant() {
    let harness = Harness::with_map(
        Repo::new("comments"),
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{ALICE} # admin,dev-alice (managed by terraform)\n"
        ),
        "TOKEN=ENC[a,type:str]\n",
    );
    harness.registry(&[
        ("admin", ADMIN, &["admin"]),
        ("dev-alice", ALICE, &[]),
        ("dev-carol", CAROL, &[]),
    ]);

    let output = harness.run(&[
        "grant",
        CAROL,
        "--label",
        "dev-carol",
        "--only",
        "secrets/dev.env",
    ]);
    let err = stderr(&output);
    assert_eq!(output.status.code(), Some(0), "{err}");

    let map = harness.repo.read(".sops.yaml");
    assert!(
        map.contains("# admin,dev-alice (managed by terraform)"),
        "free text must survive: {map}"
    );
    assert!(map.contains(CAROL), "{map}");
    assert!(
        !map.contains("dev-carol"),
        "no comment label from config: {map}"
    );
}

#[test]
fn a_label_comment_survives_a_registry_grant() {
    let harness = Harness::with_map(
        Repo::new("label-comment"),
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{ALICE} # admin,dev-alice\n"
        ),
        "TOKEN=ENC[a,type:str]\n",
    );
    harness.registry(&[
        ("admin", ADMIN, &["admin"]),
        ("dev-alice", ALICE, &[]),
        ("dev-carol", CAROL, &[]),
    ]);

    let output = harness.run(&[
        "grant",
        CAROL,
        "--label",
        "dev-carol",
        "--only",
        "secrets/dev.env",
    ]);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let map = harness.repo.read(".sops.yaml");
    assert!(
        map.contains("# admin,dev-alice"),
        "the existing labels stay (the new key has none): {map}"
    );
}

#[test]
fn a_config_comment_conflict_is_reported_as_drift() {
    let harness = Harness::with_map(
        Repo::new("drift"),
        &format!(
            "creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {ADMIN},{ALICE} # admin,recovery\n"
        ),
        "TOKEN=ENC[a,type:str]\n",
    );
    harness.registry(&[("admin", ADMIN, &["admin"]), ("dev-alice", ALICE, &[])]);

    let output = harness.run(&["status"]);
    let out = stdout(&output);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        out.contains("lockset.toml labels it dev-alice") && out.contains("comment says recovery"),
        "{out}"
    );
}
