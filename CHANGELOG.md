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

- **`lockset set` requires an explicit value source off a terminal.** A
  non-interactive run now needs `--stdin`, `--from-env NAME`, or the new
  `--value-file PATH`; it no longer reads stdin just because stdin is not a
  TTY. Previously `set K --payload … < /dev/null` stored `K=` and said nothing.
  An empty value is refused unless `--allow-empty` is passed, and the three
  sources are mutually exclusive.

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

### Fixed

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
