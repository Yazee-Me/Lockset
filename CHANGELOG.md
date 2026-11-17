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
