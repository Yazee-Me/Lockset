---
description: "Lockset project context: workspace, invariants, gates, and repository conventions"
applyTo: "**"
---

# Lockset

Guidance for agents working in this repository. Lockset gives repository secrets
a small, boring surface: per-principal grants on top of sops and age. It is a
CLI and a Rust library; there is no server and no second secret store.

Where this section differs from the shared Playbook rules, this section wins.
The deviations are deliberate and named with the rule they override.

## Workspace

- `lockset-core` — the model: `.sops.yaml` parse and rewrite, payload metadata,
  plans, and reports. No I/O, no environment, no OS code.
- `lockset-tools` — the adapters: `FsRepo`, `SopsCodec`, and custody over the
  OS keychain, `LOCKSET_AGE_KEY`, a file, or memory.
- `lockset` — the CLI and the orchestration as a library. `lockset::run` takes
  the parsed arguments plus `Inputs`; `main` is parse → run → exit code.
- `fuzz/` — libFuzzer targets for the input-heavy parsers.
- `scripts/` — the CI install, export, container, and artifact helpers.
- `confluence-docs/` — the local review and publish bundle for the Confluence
  space **LS — Lockset** (`spaceId` 171638788). It is not part of the build.

## Architecture invariants

- **`lockset-core` never does I/O.** No process spawn, filesystem, environment,
  or OS checks. Every external capability is a port (`Codec`, `Custody`,
  `Repo`) implemented in `lockset-tools`; the CLI injects the environment as
  `Inputs`.
- **Plans are data.** A command builds a `Plan` of `Change` values; the CLI
  renders it (`--dry-run`) or hands it to `exec::apply`, the only place that
  mutates anything.
- **Errors carry an exit class.** A `lockset_core::Error` variant maps to the
  exit codes in `README.md` through `usage::exit_code`. A new failure needs a
  class, not a bare `anyhow` string, unless it is a genuine runtime failure
  (exit 1).
- **No secret in argv or a file.** The identity reaches external tools through
  the child environment only; values are never written to disk; sops output is
  redacted before it is formatted.
- **Paths and rewrites are conservative.** `PathId` accepts both separators and
  refuses absolute, traversing, or ambiguous forms; rewrites touch only the
  lines they must and preserve line endings.

## Toolchain and gates

- `mise install` provides the pinned rust (1.99.1), `sops` (3.13.3), and `age`
  (1.3.2). The workspace MSRV is 1.89 and every dependency must build with it.
- Run repository tasks through `mise run`; a missing task is a gap to add to
  `mise.toml`, not a bare command to ship.
- `mise run check` is the full local gate: tests, lint (format, clippy, rustdoc),
  end-to-end, `cargo-deny`, and `cargo-audit`.
- `mise run e2e` runs the real pinned `sops` and `age`; `mise run fuzz` sweeps
  the parsers and needs the nightly toolchain and `cargo-fuzz`.
- CI runs the same versions from `mise.toml` on GitHub-hosted runners. The
  shared Playbook rule that puts every job on Blacksmith does not apply to this
  repository: it has no Blacksmith app, and the workflows use the GitHub-hosted
  `ubuntu-24.04`, `macos-15`, and `windows-2022` images.
- This repository has no TypeScript, no database, and no Sentry integration.
  The shared rules for those areas do not apply.

## Changing behaviour

- **New config field:** parse and validate it in `lockset-core/src/config.rs`
  with an error that names the field, resolve precedence in
  `lockset/src/wiring.rs`, document it in the README configuration reference,
  and test the default, the override, and an invalid value.
- **New command or flag:** add it to `cli.rs`, the dispatcher and handler in
  `app.rs`, the help and exit-code contract, and the README. Tests cover the
  plain path, the failure, and `--json` where a document applies.
- **New parser input:** add a proptest property in
  `lockset-core/tests/parsers.rs` and, if it parses untrusted text, a fuzz
  target in `fuzz/`.
- **Security boundary:** pin it in `lockset/tests/sops_contract.rs` (argv and
  environment) or the relevant contract test.

## Tests

- `lockset/tests/` runs the real binary against temporary repositories. Tests
  that need `sh`, permissions, or symlinks are gated `#![cfg(unix)]`; the
  shim-free tests must keep working on Windows.
- Shims (`LOCKSET_SOPS` pointing at a script) cover sops interactions
  deterministically. `lockset/tests/sops_contract.rs` records argv and
  environment and is the place to pin a security boundary.
- A new test must fail when the behaviour regresses, not just call the code. It
  must be deterministic and safe under `--test-threads`.

## Tickets

- Work is tracked in Jira at `yazee.atlassian.net`, project key `LS`, under an
  epic. Use the shared `jira-tickets` skill for the templates and the board
  workflow.
- Title it `[<AREA>] <description>`. Area tags in use: `[CLI]`, `[CORE]`,
  `[TOOLS]`, `[SECURITY]`, `[RELEASE]`, `[CI]`, `[DOCS]`, `[TOOLING]`.
- The board has `To Do`, `In Progress`, `In Review`, and `Done`. Move the ticket
  to `In Progress` when the branch is cut and `Done` after the merge.

## Lockset branches, commits, and pull requests

This repository's format overrides the shared git rule.

- One ticket per branch. The branch is named `LS-<n>` and is cut from the
  previous ticket's branch; the repository uses stacked pull requests, so the
  pull request targets that previous branch.
- Commit subject: `<type>(<scope>): <summary> (LS-<n>)`, for example
  `fix(run): keep the child's signal (LS-22)`. Types in use: `feat`, `fix`,
  `refactor`, `test`, `docs`, `ci`, `chore`.
- Pull request title: the ticket title followed by the key, for example
  `[CLI] Add export for multi-step pipelines (LS-20)`.
- Never merge a pull request and never enable auto-merge. Open it, report the
  URL, and stop.

## Lockset releases

This repository's release flow overrides the shared `release.json` rule; there
is no `release.json` here.

- `cargo release patch --execute` (or `minor`/`major`) bumps every crate, opens
  the next `CHANGELOG.md` section from `Unreleased`, commits, tags `v<version>`,
  and pushes. The tag drives cargo-dist, the container image, and the action.
- Keep `Unreleased` accurate: it is the release body, and CI checks that the
  version's notes document the breaking change.
- The verification tasks are `mise run release:plan`, `release:build`, and
  `release:verify`. Crates publish in order: `lockset-core`, `lockset-tools`,
  `lockset`.

## Documentation

- The repository keeps what a deploy or a contributor needs: `README.md`
  (install, configure, operate), `SECURITY.md` (threat model and reporting),
  `CONTRIBUTING.md` (development and architecture rules), `CHANGELOG.md`
  (release notes), and rustdoc.
- The business and technical overview lives in the Confluence space **LS —
  Lockset**. Address the space by key. Publish page writes through the
  Atlassian MCP server and verify them with `acli`.
- `confluence-docs/` is the local, reviewable copy of that space; keep it in
  step when a documented contract changes, but do not treat it as build input.

## Generated output

- `AGENTS.md` and `.agents/skills/` are generated by APM. Never edit them by
  hand; edit `.apm/instructions/` or the Playbook package.
- `Cargo.lock` is committed and updated by Cargo, never by hand; build caches
  and `target/` stay out of the tree.
