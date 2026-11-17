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
