# Security policy

Lockset decrypts repository secrets for pipelines and machines. This document
states what it protects, what it explicitly does not, and how to report a
problem.

## Supported versions

Only the latest release receives security fixes. Lockset is pre-1.0: a fix may
land as a patch release, and a breaking change to a security promise is called
out in `CHANGELOG.md` under "Breaking changes".

## Reporting a vulnerability

Open a **private security advisory** at
<https://github.com/Yazee-Me/Lockset/security/advisories/new>. Do not open a
public issue for an exploitable problem. Include the version
(`lockset --version`), what you observed, and a reproduction if you have one.

This is a small project without a paid response team: reports are handled on a
best-effort basis, and you will get an acknowledgement before any public
disclosure. Please give a fix and a release a reasonable window before
publishing details.

## What lockset is

- A CLI and library over **sops**: sops encrypts/decrypts payloads, `.sops.yaml`
  keeps the recipient map, and age holds the keys. Lockset adds grants,
  reporting, a runner, and transactional edits of the map.
- The private identity lives in one of: the `LOCKSET_AGE_KEY` variable (or the
  variable `custody.env` names), the OS keychain (`security(1)` on macOS, the
  platform credential store on Linux and Windows), a file outside the repository
  (`--custody file:<path>`, mode 0600), or memory.
- Every mutation is planned as data and applied by `exec::apply`, which backs up
  each touched file and restores it if any step fails.

## Threat model

Assets: the age identity, the plaintext payload values, and the recipient map.

| Adversary | In scope? | What stops it |
| --- | --- | --- |
| A same-user process on the machine | partly | The identity is never in argv or a file lockset writes; the sops child gets it only as `SOPS_AGE_KEY`; the child `run` starts never inherits the identity or a `SOPS_*` override; payload values exist only in the child's environment. A same-user process can still read `LOCKSET_AGE_KEY` from the parent's environment or `/proc`, and can read a file-custody key it owns — **treat a machine that runs lockset as trusted**. |
| The command lockset runs | yes | `run` gives it the payload values but not the identity; a payload that defines an identity or `SOPS_*` name is refused; `--pass-custody` is the deliberate opt-out and is documented as such. |
| Someone reading CI logs | yes | `run` never prints values; `export` warns on stderr; the composite action masks every exported value with `::add-mask::` before `$GITHUB_ENV`; sops errors are redacted (`[redacted]` for the identity and any `AGE-SECRET-KEY-…` token); plans redact values (`--json` emits `"value": null`). |
| Someone reading git history | not erased | Revoking a recipient rotates the data key, which bounds *future* exposure; ciphertext already committed, and plaintext already copied, stay readable to whoever already had them. |
| A malformed or hostile payload/map | yes | Paths are repository-relative values that cannot traverse, be absolute, or start with `-`; payloads are dotenv only; a mixed or non-age rule is reported and refused where it would be rewritten; writes are digest-checked and atomic; rewrites keep line endings and untouched bytes. |
| A tampered release download | partly | Every archive ships a `.sha256` and a combined `SHA256SUMS`; the release carries GitHub artifact attestations (`gh attestation verify`); minisign signatures are published when the repository has a signing key. macOS binaries are **not notarized** and Windows binaries are **not Authenticode-signed** — see "Signing" in the README. |
| Root/Administrator, a hypervisor, or a memory dump | no | Nothing at this layer defends a compromised host. |
| sops, age, the OS keychain | no | They are the trust base; a vulnerability there is theirs to fix (and is reported by `cargo audit`). |

### `run` versus `export`

- **`run`** is the safe default: the values exist only in one child's
  environment, the identity is stripped from it, and the child's exit code and
  signals pass through. Prefer it whenever one command can consume the values.
- **`export`** prints values to stdout for multi-step pipelines. That is a
  deliberate disclosure to whatever reads the pipe: mask the values before a
  runner echoes them (the composite action does this), keep the files out of
  git, and do not use `export` inside a step whose output is uploaded.

### Identity handling

- The identity never reaches argv: sops gets it as `SOPS_AGE_KEY`; on macOS
  `key import` asks `security(1)` to prompt for it instead of passing it as an
  argument, and a non-interactive run refuses to store it rather than leak it.
- The sops child starts without the parent's `LOCKSET_AGE_KEY` or any `SOPS_*`
  variable, so an inherited `SOPS_AGE_KEY_FILE`/`SOPS_AGE_KEY_CMD` cannot
  redirect it.
- `file:` custody resolves symlinks before checking that the key is outside the
  repository, refuses symlinks and non-regular files, refuses a key readable by
  group/others, and creates new key files with mode 0600 from the start.
- A machine cannot revoke its own identity without `--force`; a failed
  self-revoke either lands whole or is rolled back.

### Container image

The image carries binaries only: no identity, no repository content, no build
tools, a non-root user (uid 10001), and it is documented to receive keys only
through the environment or a read-only mount. Its smoke test asserts that no
private key appears in the image history.

## Dependency and supply-chain policy

- `cargo deny check` (licenses, bans, sources, advisories) and `cargo audit` run
  in CI; the policy lives in `deny.toml` and `.cargo/audit.toml`.
- Ignored advisories are listed with a reason and a condition for revisiting.
  Vulnerability advisories: one (a P-256 timing issue in `age`'s pinned
  `crypto-bigint`, which lockset's x25519-only identity support does not reach).
  Unmaintained-crate advisories: the transitive zbus/zvariant set behind the
  Linux keychain and a build-time i18n helper in `age`.
- Dependabot opens grouped updates for cargo, the fuzz crate, and the actions.

## Out of scope

- Protecting secrets on a host where the same user (or root) is already
  adversarial.
- Erasing plaintext that has been copied, or ciphertext already in git history.
- Code signing/notarization of release binaries (documented as a limitation).
- Third-party tools: `sops`, `age`, the OS keychain, `git`, and CI providers.
