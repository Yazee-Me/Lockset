# Lockset

Repository secrets with a small, boring surface: per-principal grants on top of
sops and age. Lockset is a CLI and a Rust library. sops stays the codec and
`.sops.yaml` stays the recipient map — there is no Lockset server and no second
secret store.

## What it does

- Reports who may read what, and drift between the map and the payloads:
  `status`, `who`, `check`.
- Runs a command with one or more payloads in its environment, never with the
  identity: `run`.
- Prints selected values for a multi-step pipeline as `dotenv`, `json`, or shell
  assignments: `export`.
- Sets a single value and reads it back to prove it landed: `set`. On a
  terminal it prompts with the input hidden; a pipeline names its source with
  `--stdin`, `--from-env NAME`, or `--value-file PATH`, and an empty value needs
  `--allow-empty`.
- Rotates data keys without touching values: `rotate`.
- Grants and revokes recipients, rewriting only the `age:` line of
  `.sops.yaml`, re-wrapping the affected payloads, and rotating the data key on
  revoke: `grant`, `revoke`, `person add`, `person remove`.
- Keeps the local identity in the OS keychain, an explicit file, or the
  environment: `key import`, `key status`, `key forget`.

Every mutating command prints its plan; `--dry-run` stops there.

## Layout

| Crate | Role |
| --- | --- |
| `lockset-core` | Model, `.sops.yaml` parse/rewrite, payload metadata, plans, reports. No I/O, no environment, no OS code; every external capability is a port (`Codec`, `Custody`, `Repo`). |
| `lockset-tools` | The adapters: `FsRepo`, `SopsCodec` (the only external tool in the loop), and custody over the keychain, `LOCKSET_AGE_KEY`, a file, or memory. |
| `lockset` | The CLI. |

## Requirements

- `sops` 3.13 or newer on `PATH` (override with `--sops <path>` or
  `LOCKSET_SOPS`). Mutations check the binary and its version before they start.
- An age identity: `LOCKSET_AGE_KEY` when set, the keychain item
  `lockset-age-key`, or an explicit `--custody file:<path>`. Give `file:` an
  absolute path outside the repository — a mounted secret such as
  `/run/secrets/age-key`, for instance: the key file is created with mode 0600,
  and a symlink, a non-regular file, a path inside the repository, or a file
  readable by other users is refused. Without an identity the read-only commands
  still work: `status` and `who` report no identity, and `check` records it as a
  finding. A non-interactive run never falls back to the keychain implicitly; it
  reports no identity and asks for `LOCKSET_AGE_KEY`, `--custody file:<path>`, or
  an explicit `--custody keyring`. An unknown `--custody` form exits 2 and lists
  the valid ones.
- A repository with `.sops.yaml` at its root, payloads as `secrets/**/*.env`,
  and recipients labelled by a trailing `# label,...` comment in recipient
  order. Payload paths are repository-relative: an absolute path, `..`, a
  backslash, an empty segment, or a leading `-` is a usage error (exit 2) before
  any sops call.
- The only payload format is dotenv (`.env`). Every other non-hidden file under
  `secrets/` is reported as an unsupported payload in `status` and `check`, and
  `run`/`set` reject it with a message naming the format, so no payload is
  silently ignored or half-counted. Hidden files (`.gitkeep`, editor
  temporaries) are not payloads.

## Use

```sh
cargo install --path lockset --locked

lockset doctor                       # preflight: repo, sops, custody, identity, coverage, CI policy
lockset status                       # identity, payloads, coverage, drift, empty values
lockset who                          # label -> public key, payload count, local key
lockset run --payload secrets/dev.env -- ./my-command
lockset run --pass-custody -- ./tool  # deliberate exception: the child gets the identity environment
lockset set NEW_KEY --payload secrets/dev.env      # hidden prompt
printf '%s' "$NEW_KEY" | lockset set NEW_KEY --payload secrets/dev.env --stdin
lockset set NEW_KEY --payload secrets/dev.env --from-env NEW_KEY
lockset set NEW_KEY --payload secrets/dev.env --value-file /run/secrets/new-key
lockset --dry-run --json set NEW_KEY --payload secrets/dev.env   # plan as JSON, value redacted
lockset export --payload secrets/prod/deploy.env --format dotenv
lockset grant age1... --label dev-alice
```

With mise (pinned toolchain):

```sh
mise install
mise run test        # cargo test --workspace
mise run build       # release build of the CLI
mise run install     # link target/release/lockset into ~/.local/bin
```

## Machine-readable output

`status`, `who`, and `check` take `--json`, and a plan is JSON with
`--dry-run --json`. Every document carries `"schema_version": 1` and only
redacted data: identities are public keys, payload rows are counts, and a
`SetValue` change serializes `"value": null`. stdout is the document alone;
notes and warnings go to stderr.

```sh
lockset status --json | jq '.drift'
lockset check  --json | jq -e 'all(.checks[]; .ok)'
lockset --dry-run --json grant age1... --label dev-alice
```

## Pipelines

`run` is the safe default for a single command: values exist only in the child's
environment. When several steps need them, `export` prints the selected payload
values — and only those, never the identity — in the requested format.

```sh
# GitHub Actions: mask every value, then append it to the job environment
lockset export --payload secrets/prod/deploy.env --format dotenv |
  while IFS='=' read -r name value; do
    echo "::add-mask::$value"
    echo "$name=$value" >> "$GITHUB_ENV"
  done

# Docker/Compose: an env file next to the compose file
lockset export --payload secrets/prod/deploy.env --format dotenv > .env.deploy

# A shell step
eval "$(lockset export --payload secrets/dev.env --format sh)"
```

Payloads merge in the order given, last value wins. The output is secret
material: `export` warns on stderr, so mask values before a runner echoes them,
keep the files it writes out of git, and prefer `run` whenever one command can
consume the values.

## Doctor

`lockset doctor` is the preflight a pipeline runs before touching secrets. It
checks the repository and `.sops.yaml`, that `sops` is present and at least
3.13, which custody is in use and whether it is readable, that only the current
identity sources are read, the identity itself, its coverage, the payloads, the
default payload (`secrets/prod/infra.env`), and the CI custody policy (a
non-interactive run must have an identity source). It exits 1 and names every
failing check; `doctor --json` is the same report as a `schema_version: 1`
document.

```sh
lockset doctor
lockset doctor --json | jq -e 'all(.checks[]; .ok)'
```

## Exit codes

Pipelines can gate on the exit code; `lockset --help` prints the same table.

| Code | Meaning |
| --- | --- |
| 0 | ok |
| 1 | findings: a failed `check`, a `status --strict` finding, or a runtime failure |
| 2 | usage or configuration: bad argument, no `.sops.yaml`, unsupported payload format |
| 3 | custody or authentication: no identity, keychain or file custody failure |
| 4 | external tool: `sops` missing or failing |
| 5 | conflict or lock: an input changed, another process holds the repository |
| 6 | partial apply: a mutation could not be undone; the message names the files |

`status --strict` exits 1 on drift, empty values, a missing identity, or
unreadable payloads; without `--strict` it always reports and exits 0. `check`
covers identity presence, unreadable payloads, ciphertext, plaintext, empty
values, label drift, admin coverage, and a decrypt proof for whatever identity
this machine has — no particular label is required.

## Design notes

- `lockset-core` never spawns a process, reads the environment, or touches the
  filesystem; `lockset-tools` implements the ports. That is what makes the model
  testable without credentials and reusable from another front end.
- Plans are data (`Change` values) and `exec::apply` is the only place
  mutations happen, so `--dry-run` and tests share one path.
- Every mutation is transactional: `exec::apply` reads the bytes of each file a
  plan touches before writing, and restores them if any step fails, so a command
  either lands whole or leaves the repository as it was. When a restore itself
  fails the command reports a partial apply (exit 6) naming the files and the
  recovery step, and never returns success.
- Mutating commands hold an advisory lock for the whole read-plan-apply cycle —
  `.git/lockset.lock` (following a worktree's `gitdir:`) or `.lockset.lock`
  without a git directory. A second process waits `--lock-timeout` seconds
  (default 10) and then exits 5 with a conflict instead of racing.
- A plan records the digest of every file it touches. If one changed after the
  snapshot — an editor, another tool — the apply writes nothing and exits 5.
- `--dry-run` builds the plan before custody is consulted, so every mutating
  command renders its plan with no identity at all and a pipeline can diff a
  change without secrets. The key is required only to apply, and an invalid
  plan keeps its own exit code instead of hiding behind a missing identity.
- Payload discovery skips symlinks and dedupes canonical paths, so a
  self-referential link cannot duplicate or loop the inventory. A payload that
  cannot be read or parsed is a finding with its path and error (`status`,
  `check`), and the remaining payloads are still reported and rotated.
- Writes are durable: the temp file is fsynced before the rename and the parent
  directory after it, and a CRLF `.sops.yaml` is rewritten with CRLF.
- Paths are `PathId` values parsed relative to the repository root, so no
  `Repo` or `Codec` call can be handed a traversal or a value sops would read
  as an option.
- Rewrites touch only the `age:` line of `.sops.yaml` and are followed by a
  decrypt, because a structurally valid file with lost values only shows up on
  read.

## Security notes

- Values are never written to a file: `run` passes them through the child
  environment, which same-user processes can read. Treat a machine that runs
  this as trusted.
- `run` gives the command an explicit environment: the parent's, minus
  `LOCKSET_AGE_KEY` and every `SOPS_*` variable, plus the payload values. The
  identity opens every payload, so a build script must not inherit it.
  A payload that itself defines an identity or `SOPS_*` name is refused rather
  than exported. `--pass-custody` inherits the parent environment unchanged and
  is the deliberate exception; if a command has to decrypt for itself, hand it
  the path of an identity file explicitly instead.
- The private key reaches sops as `SOPS_AGE_KEY`, and the sops child starts
  without the parent's identity or any other `SOPS_*` variable, so no inherited
  override can redirect it. The key never reaches argv or a file.
- `--custody file:<path>` keeps the identity outside the repository and
  private: the path is resolved through symlinks before that check, symlinks
  and non-regular files are refused, and a key file must be 0600 or stricter.
  New files are created with mode 0600, never written first and chmodded after.
- Plans carry a value as a redacted `SecretValue`: `{:?}` prints `<redacted>`,
  `--json` emits `"value": null`, and the buffer is zeroized when the plan is
  dropped. `--json` describes a plan, so it requires `--dry-run` and is not
  available on the report commands.
- `key import` never puts the identity in an argument list: on macOS the
  keychain write asks `security(1)` to prompt for it, so `ps` cannot show it to
  a same-user process. A non-interactive run refuses to store it and points at
  `--custody env` or `--custody file:<path>`, which need no prompt.
- A machine cannot revoke its own identity without `--force`: decommission it
  from another admin machine instead, because a failed self-revoke used to leave
  the repository half-updated and the machine locked out. It now either lands
  whole or is restored.
- Revoking a recipient rotates the data key, which bounds future exposure. It
  cannot erase ciphertext already in git history or plaintext already copied.

## Provenance

Imported from `Yazee-Me/Servers` at commit `e6be297`, where the workspace lived
under `tools/secrets`. Product decision and ticket: `LOC-1`.
