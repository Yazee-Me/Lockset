# Changelog

## Unreleased

### Breaking changes

- **Identity and sops lookup use the Lockset names only.** The private key is
  read from `LOCKSET_AGE_KEY` or the `lockset-age-key` keychain item, and the
  sops binary from `LOCKSET_SOPS`; the names used before the rename are ignored,
  with no fallback and no deprecation warning. A machine still relying on them
  reports no identity: `status` prints `identity: none`, and `run`, `set`,
  `rotate`, `grant`, and `revoke` stop with `no identity in custody`.

  Before upgrading, rename the environment variables to the names above. On
  every machine that kept its identity in the pre-rename keychain item, run
  `lockset key import` once — pasting the same age identity — so the current
  item holds it. `--custody file:<path>` needs no change beyond the variable
  name.

- **No command defaults to a production payload.** `run` and `set` used to fall
  back to `secrets/prod/infra.env`; they now use `repo.default_payloads` from
  `lockset.toml`, and a repository that names none stops with exit 2 and lists
  the payloads it does have. `set` needs exactly one default. Add
  `lockset.toml` with `default_payloads = ["secrets/dev.env"]`, or pass
  `--payload`.

- **`lockset set` requires an explicit value source off a terminal.** A
  non-interactive run now needs `--stdin`, `--from-env NAME`, or the new
  `--value-file PATH`; it no longer reads stdin just because stdin is not a
  TTY. Previously `set K --payload … < /dev/null` stored `K=` and said nothing.
  An empty value is refused unless `--allow-empty` is passed, and the three
  sources are mutually exclusive.

### Added

- **`lockset.toml` carries the repository's conventions.** Every field is
  optional: `repo.sops_config`, `repo.payload_globs`, `repo.default_payloads`,
  `labels.admin`, `labels.person_prefix`, `custody.kind`, `custody.env`,
  `custody.keychain_item`, `codec.sops`, and `codec.min_version`. The layers
  are flags, then environment (`LOCKSET_CONFIG`, `LOCKSET_REPO`, `LOCKSET_SOPS`,
  the identity variable), then the file, then the defaults. `--config` selects
  a different file, and `LOCKSET_REPO` supplies the root when `--repo` is absent.
  A config error names the file and the field and exits 2.
- `doctor` reports the sops config it read and the configured default payloads,
  and its custody findings use the configured variable and keychain item names.

- `lockset run --clean-env` gives the command only `PATH`, `HOME`, `TMPDIR`, and
  `LANG` from the parent plus the payload values, for jobs that would otherwise
  inherit an unrelated CI secret.
- `--quiet`, `--verbose`, and `RUST_LOG` select the stderr level: notes and
  warnings show by default, `--quiet` keeps only errors, and `--verbose` (or
  `RUST_LOG=debug`) adds the repository root, custody kind, and sops binary.
  A flag wins over `RUST_LOG`; `--quiet` and `--verbose` conflict (exit 2).
  stdout is unchanged by any of them.
- `lockset set --if-absent` stores nothing when the payload already gives the
  key a non-empty value, so a retried step cannot overwrite a configured
  secret. An empty value counts as absent, and reading the payload needs the
  identity even for `--dry-run`.

### Added

- Custody forms: `--custody env:<NAME>` reads a named variable, so two
  pipelines on one machine can keep distinct sources, and `LOCKSET_CUSTODY`
  selects custody from the environment (the flag still wins; an empty value is
  unset). `custody.kind` accepts the same grammar, and
  `custody.keychain_item`/`custody.keychain_account` give a repository its own
  keychain item, including for `keyring:<service>`.
- The custody policy is documented and enforced the same way everywhere: flag,
  `LOCKSET_CUSTODY`, the identity variable, `custody.kind`, then `auto` — which
  is the keychain on a terminal and no source off one. Invalid or incomplete
  specs (including a bare `file:`) exit 2 and list the forms.

- **The identity registry lives in `lockset.toml`.** `[[identities]]` entries
  carry `label`, `public`, and optional `roles`; duplicate labels or keys and
  invalid fields are refused by name (exit 2). Once the registry exists it is
  the source of truth: `who` lists it, `grant` requires the identity to be
  registered (and refuses a label registered to another key), `revoke --label`
  resolves through it, and the `admin` role decides admin coverage instead of
  the `labels.admin` label.
- `lockset who --toml` prints a `[[identities]]` block from the current
  `.sops.yaml` comments, for the documented one-time migration; it changes no
  recipients, and unlabelled recipients are named on stderr.

- A sops rule keyed by another backend (`pgp`, `kms`, `gcp_kms`, `azure_kv`,
  `hc_vault_transit_uri`) no longer fails the whole file: it parses, `status`
  lists its payloads, and `check` reports it per rule with the backend and what
  still works. `grant` and `revoke` refuse only a rule whose `age:` line they
  would have to rewrite, naming the rule and backend; `rotate` and `set` are
  unaffected.
- `repo.sops_config` is passed to sops as `--config` when it is not the default
  `.sops.yaml`, which sops discovers by itself in the working directory, so a
  map at `sops/settings.yaml` works for reads and for `updatekeys`/`rotate`/`set`.

### Fixed

- Rewriting the sops config no longer destroys comments that are not a label
  list: free text after the age keys is preserved verbatim, a partial label
  list is kept instead of being regenerated misaligned, and a comment conflict
  with the registry is reported as drift rather than silently overwritten.
- `revoke` wrote `.sops.yaml` even when `repo.sops_config` named another file;
  it now writes the configured path, like `grant`.

### Changed

- Payload discovery walks the repository and keeps what `repo.payload_globs`
  matches, so conventions outside `secrets/**` need no code change; the admin
  coverage check uses `labels.admin`.
- `lockset run` hands the child its own exit status: on Unix the CLI `exec`s the
  command, so its exit code and terminating signals pass through untouched;
  elsewhere the wait status is propagated, mapping a signal to `128 + signal`.
- A sops failure now keeps every stderr line, indented under an error that names
  the payload, with the identity and any `AGE-SECRET-KEY-…` token replaced by
  `[redacted]`. Previously only the first line survived, and a mutation that
  rolled back cleanly reported exit 1: an external-tool failure now keeps exit
  4.

### Security

- `lockset run` no longer hands the identity to the command it starts: the
  child's environment is the parent's minus `LOCKSET_AGE_KEY` and every
  `SOPS_*` variable, with the payload values added on top; a payload that
  defines one of those names is refused. Scripts that relied on the child
  reading the identity must ask for `--pass-custody`, or be given the path of
  an identity file. `sops` also starts from the scrubbed environment, with
  `SOPS_AGE_KEY` as its only key source, so an inherited `SOPS_AGE_KEY_FILE` or
  `SOPS_AGE_KEY_CMD` can no longer redirect it.
- `lockset key import` no longer passes the private key to `security(1)` as an
  argument: on macOS `security` prompts for it, so `ps` cannot show it to a
  same-user process. A non-interactive run refuses the keychain instead of
  leaking the key, and points at `--custody env` or `--custody file:<path>`;
  keychain lookup and delete now match the account as well as the service.
- Payload paths are validated before any sops call: an absolute path, `..`, a
  backslash, an empty segment, or a leading `-` now exits 2 and names the
  offending value. `PathId` can no longer be built unchecked, so `Repo` and
  `Codec` operations only ever receive repository-relative paths.
- `--custody file:<path>` enforces what its docstring promised: the path is
  resolved through symlinks and refused when it lands inside the repository,
  symlinks and non-regular files are refused, a key file readable by group or
  others (mode 0600 required) is rejected with a `chmod 600` hint, and a new key
  file is created with mode 0600 through the open options instead of being
  chmodded after the secret was written.

- Plan values are redacted and zeroized: `Change::SetValue` holds a
  `SecretValue` that prints as `<redacted>`, serializes as `null`, and zeroes its
  buffer when the plan is dropped, so `Debug` and plan JSON cannot reveal it.
  `--dry-run --json` prints the redacted plan; `--json` needs `--dry-run` and is
  not available on the report commands.

### Added

- `lockset doctor [--json]` preflights the repository, the sops version,
  custody, the identity, coverage, the payloads, the default payload, and the
  CI custody policy, exiting 1 and naming every failing check. Mutations run the
  same sops presence/version preflight once before they start, and `--sops
  <path>` takes precedence over `LOCKSET_SOPS` and the `sops` on `PATH`.
- `lockset export --payload PATH --format dotenv|json|sh` prints selected
  payload values for multi-step pipelines, merging payloads in order (last
  wins), refusing identity and sops names, and warning on stderr that the
  output is secret material. The README shows GitHub `::add-mask::` usage and
  recommends `run` for single-command jobs.
- `status`, `who`, and `check` accept `--json`, and plan documents carry
  `"schema_version": 1`. Each report is a stable serde structure (`StatusReport`,
  `IdentityReport`, `CheckReport`, `PlanDocument`) with counts and public keys
  only: private keys, plaintext values, and `SetValue.value` are never
  serialized. Plan notes and warnings moved to stderr so stdout is machine
  readable; the text views are otherwise unchanged.

### Fixed

- The exit-code contract is defined and documented in `--help` and the README:
  0 ok, 1 findings, 2 usage/config, 3 custody/auth, 4 external tool, 5
  conflict/lock, 6 partial apply. Custody and sops failures now carry their own
  error class instead of sharing exit 1.
- `status --strict` exits 1 on drift, empty values, a missing identity, or
  unreadable payloads, and `check` now includes empty values and decrypt-verifies
  with whatever identity is present instead of only a recipient labelled
  `admin`.

- Payload formats are explicit: dotenv (`.env`) is the only supported format.
  `meta` no longer half-parses a YAML `sops:` block, discovery lists every
  non-hidden file under `secrets/` so an unsupported payload is reported as a
  finding instead of being ignored, and `run`/`set` reject non-`.env` payloads
  with a message naming the format.
- A payload that cannot be parsed no longer aborts `status`, `who`, or `check`:
  it becomes a finding with its path and error, `check` gains a `payloads
  parse` check, and unrelated payloads — including `rotate --all` — keep
  working. Payload discovery skips symlinks and dedupes canonical paths, so a
  self-referential link cannot duplicate or loop the inventory.
- `--dry-run` builds and renders the plan before custody is consulted, so
  `grant`, `revoke`, `rotate`, `person add`/`remove`, `set`, `key import`, and
  `key forget` can be planned with no identity; the key is required only to
  apply, and `key forget --dry-run` no longer asks for confirmation.
- Mutating commands serialize on an advisory repository lock
  (`--lock-timeout`, default 10s; a timeout exits 5), and a plan records the
  digest of every file it touches so an input changed after the snapshot aborts
  the apply before anything is written (exit 5). Writes fsync the temp file and
  the parent directory around the rename, and a CRLF `.sops.yaml` stays CRLF.
- Mutating commands are transactional: `exec::apply` backs up every file a plan
  touches and restores them when a step fails, so a failed `grant`, `revoke`,
  `rotate`, or `set` leaves the repository as it was. A restore that cannot
  complete is a partial apply (exit 6) naming the files and the recovery step,
  never a success. Revoking this machine's own identity without `--force` now
  says to do it from another admin machine.
- `--custody` fails closed: an unknown form exits 2 and lists `env`, `keyring`,
  `file:<path>`, and `keyring:<service>` instead of warning and using the
  default, and a non-interactive run with no `LOCKSET_AGE_KEY` no longer probes
  the OS keychain implicitly — it reports no identity and names the sources to
  configure.
- A keyring that cannot answer no longer aborts `status` or `who`: they report
  `identity: unavailable` with the reason, and `check` records the failure
  instead of the command failing.
