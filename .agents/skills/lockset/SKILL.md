---
name: lockset
description: Install, configure, and use Lockset, the CLI for repository secrets on top of sops and age. Use when a task needs to install lockset, bootstrap a repository for it, read or write secrets with it, grant or revoke a recipient, or run it in CI.
---

# Lockset

Lockset manages repository secrets on top of sops and age: per-principal
grants, payload inspection, and a runner that puts payload values in a child's
environment without the identity. sops remains the codec; `.sops.yaml` remains
the recipient map. There is no server and no second secret store.

The release and repository are private. Use the authenticated paths below, not
the anonymous installer URLs.

## Choose the reference

| Situation | Read |
| --- | --- |
| `lockset` is missing, or an upgrade is needed | [install](references/install.md) |
| No `.sops.yaml`, no identity, or the first secret | [configure](references/configure.md) |
| Daily reads, writes, grants, revocation, rotation | [operations](references/operations.md) |
| A GitHub Actions or other CI pipeline | [ci](references/ci.md) |

## Ground rules

- Run `lockset --version` and `sops --version` before changing anything.
  Lockset needs `sops` 3.13 or newer on `PATH`; the binary has no other runtime
  dependency.
- The age identity never goes in an argument list, a repository file, or a
  command line. Use the keychain, `LOCKSET_AGE_KEY`, or an absolute
  `file:` path outside the repository.
- Every mutating command prints its plan. Use `--dry-run` first when unsure.
- `lockset run` strips the identity from the child. `--pass-custody` is the
  deliberate exception and must be justified, never a default.
- The release is private: anonymous download URLs return 404. Use `gh` with an
  account that can read `Yazee-Me/Lockset`, or the composite action with
  `github-token`.
- The CLI needs a repository. `lockset` alone prints usage and exits 2; run it
  inside a directory tree with `.sops.yaml` (or `lockset.toml`), or pass
  `--repo`.
