//! `lockset.toml`: layering (flags > environment > config > defaults), the
//! configurable conventions, and the refusal to invent a default payload.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::{strings, Repo};

/// A repository with a shim sops that decrypts to `TOKEN=<value>`.
struct Env {
    repo: Repo,
    shim: PathBuf,
    secret: String,
}

impl Env {
    fn new(name: &str, value: &str) -> Self {
        let repo = Repo::new(name);
        repo.write("secrets/dev.env", "TOKEN=ENC[a,type:str]\n");
        let shim = repo.path().join("sops-shim");
        std::fs::write(
            &shim,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'sops 3.13.3' ;;\n  -d) printf 'TOKEN={value}\\n' ;;\n  *) exit 1 ;;\nesac\n"
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

    /// Run the CLI with exactly the environment the test asks for: the identity
    /// and the shim by default, `unset` removed, and `env` last.
    fn invoke(
        &self,
        args: &[&str],
        env: &[(&str, &str)],
        unset: &[&str],
        cwd: Option<&Path>,
    ) -> Output {
        let mut command = Command::new(env!("CARGO_BIN_EXE_lockset"));
        command.args(strings(args));
        command
            .env_remove("LOCKSET_AGE_KEY")
            .env_remove("LOCKSET_SOPS")
            .env_remove("LOCKSET_CONFIG")
            .env_remove("LOCKSET_REPO")
            .env("LOCKSET_AGE_KEY", &self.secret)
            .env("LOCKSET_SOPS", self.shim.as_os_str());
        for (name, value) in env {
            command.env(name, value);
        }
        for name in unset {
            command.env_remove(name);
        }
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        command.output().unwrap()
    }

    fn repo_args(&self, args: &[&str]) -> Vec<String> {
        let mut all = vec!["--repo".to_owned(), self.repo.path().display().to_string()];
        all.extend(strings(args));
        all
    }
}

impl Drop for Env {
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
fn a_repository_without_defaults_never_falls_back_to_production() {
    let env = Env::new("no-default", "v");
    env.repo
        .write("secrets/prod/infra.env", "TOKEN=ENC[a,type:str]\n");

    let run = env.invoke(
        &[
            "--repo",
            env.repo.path().to_str().unwrap(),
            "run",
            "--",
            "true",
        ],
        &[],
        &[],
        None,
    );
    let err = stderr(&run);
    assert_eq!(run.status.code(), Some(2), "{err}");
    assert!(err.contains("no payload selected"), "{err}");
    assert!(err.contains("repo.default_payloads"), "{err}");
    assert!(err.contains("discovered:"), "{err}");
    assert!(err.contains("secrets/dev.env"), "{err}");
    assert!(
        stdout(&run).is_empty(),
        "the child must not start: {}",
        stdout(&run)
    );

    let set = env.invoke(
        &[
            "--repo",
            env.repo.path().to_str().unwrap(),
            "set",
            "TOKEN",
            "--from-env",
            "VALUE",
            "--dry-run",
        ],
        &[("VALUE", "x")],
        &[],
        None,
    );
    assert_eq!(set.status.code(), Some(2), "{}", stderr(&set));
    assert!(
        stderr(&set).contains("no payload selected"),
        "{}",
        stderr(&set)
    );
}

#[test]
fn config_default_payloads_are_used_by_run_set_and_doctor() {
    let env = Env::new("defaults", "v");
    env.config("[repo]\ndefault_payloads = [\"secrets/dev.env\"]\n");

    let run = env.invoke(
        &[
            "--repo",
            env.repo.path().to_str().unwrap(),
            "run",
            "--",
            "sh",
            "-c",
            "printf %s \"$TOKEN\"",
        ],
        &[],
        &[],
        None,
    );
    assert_eq!(run.status.code(), Some(0), "{}", stderr(&run));
    assert_eq!(stdout(&run), "v");

    let set = env.invoke(
        &[
            "--repo",
            env.repo.path().to_str().unwrap(),
            "set",
            "TOKEN",
            "--from-env",
            "VALUE",
            "--dry-run",
        ],
        &[("VALUE", "x")],
        &[],
        None,
    );
    assert_eq!(set.status.code(), Some(0), "{}", stderr(&set));
    assert!(
        stdout(&set).contains("would set TOKEN in secrets/dev.env"),
        "{}",
        stdout(&set)
    );

    let doctor = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "doctor"],
        &[],
        &[],
        None,
    );
    let out = stdout(&doctor);
    assert!(
        out.lines()
            .any(|line| line.starts_with("default payloads") && line.contains("secrets/dev.env")),
        "{out}"
    );
}

#[test]
fn a_flag_payload_wins_over_the_config_default() {
    let env = Env::new("flag-wins", "from-config");
    env.repo
        .write("secrets/other.env", "TOKEN=ENC[a,type:str]\n");
    env.config("[repo]\ndefault_payloads = [\"secrets/dev.env\"]\n");

    // The shim prints the same value for every payload, so the proof is that
    // the other payload reaches the plan.
    let output = env.invoke(
        &[
            "--repo",
            env.repo.path().to_str().unwrap(),
            "--dry-run",
            "set",
            "TOKEN",
            "--payload",
            "secrets/other.env",
            "--from-env",
            "VALUE",
        ],
        &[("VALUE", "x")],
        &[],
        None,
    );
    let out = stdout(&output);
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(
        out.contains("would set TOKEN in secrets/other.env"),
        "{out}"
    );
}

#[test]
fn set_refuses_a_config_with_several_defaults() {
    let env = Env::new("several", "v");
    env.repo
        .write("secrets/other.env", "TOKEN=ENC[a,type:str]\n");
    env.config("[repo]\ndefault_payloads = [\"secrets/dev.env\", \"secrets/other.env\"]\n");

    let output = env.invoke(
        &[
            "--repo",
            env.repo.path().to_str().unwrap(),
            "set",
            "TOKEN",
            "--from-env",
            "VALUE",
            "--dry-run",
        ],
        &[("VALUE", "x")],
        &[],
        None,
    );
    let err = stderr(&output);

    assert_eq!(output.status.code(), Some(2), "{err}");
    assert!(err.contains("one payload"), "{err}");
    assert!(err.contains("secrets/dev.env, secrets/other.env"), "{err}");
}

#[test]
fn the_config_path_layers_flag_env_then_the_repository_file() {
    let env = Env::new("config-path", "v");
    env.config("[repo]\ndefault_payloads = [\"secrets/dev.env\"]\n");
    env.repo.write(
        "conf/alt.toml",
        "[repo]\ndefault_payloads = [\"secrets/other.env\"]\n",
    );
    env.repo
        .write("secrets/other.env", "TOKEN=ENC[a,type:str]\n");
    let root = env.repo.path().to_str().unwrap().to_owned();
    let alt = env.repo.path().join("conf/alt.toml").display().to_string();

    // Environment selects the alternative file.
    let from_env = env.invoke(
        &[
            "--repo",
            &root,
            "set",
            "TOKEN",
            "--from-env",
            "VALUE",
            "--dry-run",
        ],
        &[("VALUE", "x"), ("LOCKSET_CONFIG", &alt)],
        &[],
        None,
    );
    assert_eq!(from_env.status.code(), Some(0), "{}", stderr(&from_env));
    assert!(
        stdout(&from_env).contains("secrets/other.env"),
        "{}",
        stdout(&from_env)
    );

    // The flag wins over the environment: point it at a third file.
    env.repo.write(
        "conf/flag.toml",
        "[repo]\ndefault_payloads = [\"secrets/third.env\"]\n",
    );
    env.repo
        .write("secrets/third.env", "TOKEN=ENC[a,type:str]\n");
    let flag = env.repo.path().join("conf/flag.toml").display().to_string();
    let from_flag = env.invoke(
        &[
            "--repo",
            &root,
            "--config",
            &flag,
            "set",
            "TOKEN",
            "--from-env",
            "VALUE",
            "--dry-run",
        ],
        &[("VALUE", "x"), ("LOCKSET_CONFIG", &alt)],
        &[],
        None,
    );
    assert_eq!(from_flag.status.code(), Some(0), "{}", stderr(&from_flag));
    assert!(
        stdout(&from_flag).contains("secrets/third.env"),
        "{}",
        stdout(&from_flag)
    );

    // An explicit file that does not exist is a usage error.
    let missing = env.invoke(
        &[
            "--repo",
            &root,
            "--config",
            "/nonexistent/lockset.toml",
            "status",
        ],
        &[],
        &[],
        None,
    );
    let err = stderr(&missing);
    assert_eq!(missing.status.code(), Some(2), "{err}");
    assert!(err.contains("no such config file"), "{err}");
}

#[test]
fn a_config_error_exits_two_and_names_the_field() {
    let env = Env::new("bad-config", "v");

    for (text, expected) in [
        ("[repo]\nbogus = 1\n", "bogus"),
        (
            "[repo]\npayload_globs = [\"../x/*.env\"]\n",
            "payload_globs[0]",
        ),
        (
            "[repo]\ndefault_payloads = [\"/abs.env\"]\n",
            "repo.default_payloads",
        ),
        ("[codec]\nmin_version = \"latest\"\n", "codec.min_version"),
        ("[custody]\nkind = \"magic\"\n", "custody.kind"),
        ("[labels]\nadmin = \"Not A Label\"\n", "labels.admin"),
    ] {
        env.config(text);
        let output = env.invoke(
            &["--repo", env.repo.path().to_str().unwrap(), "status"],
            &[],
            &[],
            None,
        );
        let err = stderr(&output);
        assert_eq!(output.status.code(), Some(2), "{text}: {err}");
        assert!(err.contains(expected), "{text}: {err}");
        assert!(err.contains("lockset.toml"), "{text}: {err}");
    }
}

#[test]
fn payload_globs_decide_what_is_discovered() {
    let env = Env::new("globs", "v");
    env.repo.write("conf/a.env", "TOKEN=ENC[a,type:str]\n");
    env.config("[repo]\npayload_globs = [\"conf/**/*\"]\n");

    let output = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "status"],
        &[],
        &[],
        None,
    );
    let out = stdout(&output);

    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
    assert!(out.contains("conf/a.env"), "{out}");
    assert!(!out.contains("secrets/dev.env"), "{out}");
}

#[test]
fn the_sops_config_path_is_configurable() {
    let env = Env::new("sops-config", "v");
    let map = env.repo.read(".sops.yaml");
    env.repo.write("sops/settings.yaml", &map);
    std::fs::remove_file(env.repo.sops_path()).unwrap();
    env.config("[repo]\nsops_config = \"sops/settings.yaml\"\n");

    let output = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "status"],
        &[],
        &[],
        None,
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let doctor = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "doctor"],
        &[],
        &[],
        None,
    );
    assert!(
        stdout(&doctor).contains("sops/settings.yaml"),
        "{}",
        stdout(&doctor)
    );
}

#[test]
fn the_codec_binary_layers_flag_env_then_config() {
    let env = Env::new("codec", "v");
    let root = env.repo.path().to_str().unwrap().to_owned();

    // Each shim answers with its own value, so which one ran is observable.
    let mut shims = Vec::new();
    for (name, value) in [
        ("config", "from-config"),
        ("env", "from-env"),
        ("flag", "from-flag"),
    ] {
        let path = env.repo.path().join(format!("shim-{name}"));
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'sops 3.13.3' ;;\n  -d) printf 'TOKEN={value}\\n' ;;\n  *) exit 1 ;;\nesac\n"
            ),
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        shims.push(path.display().to_string());
    }
    env.config(&format!(
        "[repo]\ndefault_payloads = [\"secrets/dev.env\"]\n[codec]\nsops = \"{}\"\n",
        shims[0]
    ));

    // Only the config names a binary.
    let from_config = env.invoke(
        &["--repo", &root, "export", "--payload", "secrets/dev.env"],
        &[],
        &["LOCKSET_SOPS"],
        None,
    );
    assert_eq!(
        from_config.status.code(),
        Some(0),
        "{}",
        stderr(&from_config)
    );
    assert_eq!(stdout(&from_config), "TOKEN=from-config\n");

    // The environment wins over the config.
    let from_env = env.invoke(
        &["--repo", &root, "export", "--payload", "secrets/dev.env"],
        &[("LOCKSET_SOPS", &shims[1])],
        &[],
        None,
    );
    assert_eq!(
        stdout(&from_env),
        "TOKEN=from-env\n",
        "{}",
        stderr(&from_env)
    );

    // The flag wins over the environment.
    let from_flag = env.invoke(
        &[
            "--repo",
            &root,
            "--sops",
            &shims[2],
            "export",
            "--payload",
            "secrets/dev.env",
        ],
        &[("LOCKSET_SOPS", &shims[1])],
        &[],
        None,
    );
    assert_eq!(
        stdout(&from_flag),
        "TOKEN=from-flag\n",
        "{}",
        stderr(&from_flag)
    );
}

#[test]
fn codec_min_version_comes_from_the_config() {
    let env = Env::new("min-version", "v");
    env.config("[codec]\nmin_version = \"9.9.9\"\n");

    let output = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "doctor"],
        &[],
        &[],
        None,
    );
    let out = stdout(&output);

    assert_eq!(output.status.code(), Some(1), "{out}");
    assert!(out.contains("older than the required 9.9.9"), "{out}");
}

#[test]
fn custody_can_come_from_the_config() {
    let env = Env::new("custody", "v");
    let key = lockset_core::SecretKey::generate();
    env.config(
        "[custody]\nkind = \"env\"\nenv = \"MY_AGE_KEY\"\nkeychain_item = \"custom-item\"\n",
    );

    let status = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "status"],
        &[("MY_AGE_KEY", key.expose())],
        &["LOCKSET_AGE_KEY"],
        None,
    );
    let out = stdout(&status);
    assert_eq!(status.status.code(), Some(0), "{}", stderr(&status));
    assert!(
        out.contains(key.public().unwrap().as_str()),
        "the configured variable must supply the identity: {out}"
    );

    let doctor = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "doctor"],
        &[],
        &["LOCKSET_AGE_KEY"],
        None,
    );
    assert!(
        stdout(&doctor).contains("custom-item"),
        "{}",
        stdout(&doctor)
    );
}

#[test]
fn the_admin_label_comes_from_the_config() {
    let env = Env::new("admin-label", "v");
    let operator = lockset_core::SecretKey::generate()
        .public()
        .unwrap()
        .as_str()
        .to_owned();
    env.repo.write(
        ".sops.yaml",
        &format!("creation_rules:\n  - path_regex: secrets/.*\\.env$\n    age: {operator} # ops\n"),
    );
    env.repo.write(
        "secrets/dev.env",
        &format!(
            "TOKEN=ENC[a,type:str]\nsops_age__list_0__map_enc=x\nsops_age__list_0__map_recipient={operator}\nsops_version=3.13.3\nsops_mac=ENC[a,type:str]\n"
        ),
    );

    let before = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "check"],
        &[],
        &[],
        None,
    );
    assert!(
        stdout(&before)
            .lines()
            .any(|line| line.starts_with("admin opens every payload") && line.contains("FAIL")),
        "{}",
        stdout(&before)
    );

    env.config("[labels]\nadmin = \"ops\"\n");
    let after = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "check"],
        &[],
        &[],
        None,
    );
    assert!(
        stdout(&after)
            .lines()
            .any(|line| line.starts_with("admin opens every payload") && line.contains("ok")),
        "{}",
        stdout(&after)
    );
}

#[test]
fn lockset_repo_selects_the_root_when_the_flag_is_absent() {
    let env = Env::new("repo-env", "v");
    let elsewhere = std::env::temp_dir().join(format!("lockset-config-cwd-{}", std::process::id()));
    std::fs::create_dir_all(&elsewhere).unwrap();

    let from_env = env.invoke(
        &["status"],
        &[("LOCKSET_REPO", env.repo.path().to_str().unwrap())],
        &[],
        Some(&elsewhere),
    );
    assert_eq!(from_env.status.code(), Some(0), "{}", stderr(&from_env));

    // The flag wins over the environment.
    let env_repo = Env::new("repo-env-other", "v");
    let args = env.repo_args(&["status"]);
    let output = env.invoke(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        &[("LOCKSET_REPO", env_repo.repo.path().to_str().unwrap())],
        &[],
        Some(&elsewhere),
    );
    assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));

    let _ = std::fs::remove_dir_all(&elsewhere);
}

#[test]
fn a_configured_default_that_is_missing_is_a_doctor_finding() {
    let env = Env::new("missing-default", "v");
    env.config("[repo]\ndefault_payloads = [\"secrets/missing.env\"]\n");

    let output = env.invoke(
        &["--repo", env.repo.path().to_str().unwrap(), "doctor"],
        &[],
        &[],
        None,
    );
    let out = stdout(&output);

    assert_eq!(output.status.code(), Some(1), "{out}");
    let line = out
        .lines()
        .find(|line| line.starts_with("default payloads"))
        .unwrap_or_default();
    assert!(line.contains("FAIL"), "{out}");
    assert!(line.contains("missing: secrets/missing.env"), "{out}");
    assert!(line.contains("discovered: secrets/dev.env"), "{out}");
}
