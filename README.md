# Lockset

Repository secrets with a small, boring surface: per-principal grants on top of
sops and age. Lockset is a CLI and a Rust library. sops stays the codec and
`.sops.yaml` stays the recipient map — there is no Lockset server and no second
secret store.

## What it does

- Reports who may read what, and drift between the map and the payloads:
  `status`, `who`, `check`.
- Runs a command with one or more payloads in its environment, never with the
  identity, and hands over the command's exit code and signals: `run`.
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
| `lockset` | The CLI, and the orchestration as a library: `lockset::run` takes the parsed arguments plus `Inputs` (variables, working directory, stdin, terminal) and two writers, so a test or an action runs the same handlers without spawning a process. `main` is only parse → run → exit code. |

## Requirements

- `sops` 3.13 or newer on `PATH` (override with `--sops <path>` or
  `LOCKSET_SOPS`). Mutations check the binary and its version before they start.
  A sops failure names the payload and keeps every stderr line, indented under
  the error; the identity is replaced with `[redacted]` first, so a tool that
  echoes its environment cannot print the key into a CI log.
- An age identity, selected by `--custody`, `LOCKSET_CUSTODY`, or the repo
  config: `env[:NAME]` (the default variable is `custody.env`,
  `LOCKSET_AGE_KEY`), `keyring[:SERVICE]` (the item is `custody.keychain_item`,
  `lockset-age-key`), `file:<absolute path>`, or `none`. Give `file:` an
  absolute path outside the repository — a mounted secret such as
  `/run/secrets/age-key`, for instance: the key file is created with mode 0600,
  and a symlink, a non-regular file, a path inside the repository, or a file
  readable by other users is refused. Without an identity the read-only commands
  still work: `status` and `who` report no identity, and `check` records it as a
  finding. A non-interactive run never falls back to the keychain implicitly; it
  reports no identity and asks for the identity variable, `--custody`, or
  `LOCKSET_CUSTODY`. An unknown or incomplete `--custody` form exits 2 and lists
  the forms; see “Custody policy” below.
- A repository with `.sops.yaml` at its root (or the `repo.sops_config` path),
  payloads as `secrets/**/*` (or `repo.payload_globs`), and recipients labelled
  by a trailing `# label,...` comment in recipient order. Payload paths are
  repository-relative and use either separator on input (`secrets\\dev.env` is
  `secrets/dev.env`); an absolute POSIX path, a drive or UNC path, `..`, a `.`,
  an empty, or a `:` segment, or a leading `-` is a usage error (exit 2) before
  any sops call. See “Portability”.
- The only payload format is dotenv (`.env`). Every non-hidden file matched by
  `repo.payload_globs` is reported as an unsupported payload in `status` and
  `check` when it is another format, and `run`/`set` reject it with a message
  naming the format, so no payload is silently ignored or half-counted. Hidden
  files (`.gitkeep`, editor temporaries) are not payloads.

## Use

```sh
# Released binary (no Rust needed); or from source:
#   curl --proto '=https' --tlsv1.2 -LsSf \
#     https://github.com/Yazee-Me/Lockset/releases/latest/download/lockset-installer.sh | sh
cargo install --path lockset --locked

lockset doctor                       # preflight: repo, sops, custody, identity, coverage, CI policy
lockset status                       # identity, payloads, coverage, drift, empty values
lockset who                          # label -> public key, payload count, local key
lockset run --payload secrets/dev.env -- ./my-command   # or repo.default_payloads
lockset run --pass-custody -- ./tool  # deliberate exception: the child gets the identity environment
lockset run --clean-env -- ./my-command  # only PATH, HOME, TMPDIR, LANG plus the payloads
lockset run --payload secrets/a.env --payload secrets/b.env --last-wins -- ./my-command
lockset set NEW_KEY --payload secrets/dev.env      # hidden prompt
printf '%s' "$NEW_KEY" | lockset set NEW_KEY --payload secrets/dev.env --stdin
lockset set NEW_KEY --payload secrets/dev.env --from-env NEW_KEY
lockset set NEW_KEY --payload secrets/dev.env --value-file /run/secrets/new-key
lockset set NEW_KEY --payload secrets/dev.env --from-env NEW_KEY --if-absent  # keep a value already set
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

## Diagnostics

Data goes to stdout; notes, warnings, and debug lines go to stderr. A pipeline
therefore sees only the document (`status --json | jq .`) or the values
(`eval "$(lockset export …)"`), and can silence the rest.

| Level | Carries | Shown by |
| --- | --- | --- |
| error | the `error:` line that ends a failing run | always |
| warn | plan warnings, the export secret-material warning | default, `RUST_LOG=warn` and above |
| info | plan notes, the `--if-absent` skip | default, `RUST_LOG=info` and above |
| debug | repository root, custody kind, sops binary | `--verbose`, `RUST_LOG=debug` and above |

`--quiet` keeps only errors and `--verbose` adds debug lines; either flag wins
over `RUST_LOG`, which otherwise selects the level (default `info`). The two
flags conflict (exit 2).

```sh
lockset status | jq '.drift'                  # stdout carries the document
lockset --quiet export --payload secrets/dev.env   # values only; the warning is silenced
lockset --verbose check                       # stderr names the repository, custody, and sops
RUST_LOG=debug lockset check                  # same, without the flag
```

`set --if-absent` stores nothing when the payload already gives the key a
non-empty value, so a retried pipeline step cannot overwrite a configured
secret; an empty value counts as absent, and the note that says so is on stderr.
Reading the payload needs the identity, so `--if-absent` asks for it even with
`--dry-run`.

## Portability

Lockset runs on Linux, macOS, and Windows. The same repository and the same
paths work on all three:

- **Separators.** Payload paths, `repo.sops_config`, and `repo.default_payloads`
  accept `/` and `\`; they are stored and compared as `/`, so
  `secrets\\dev.env` and `secrets/dev.env` are one file. Ambiguous forms are
  refused rather than guessed: absolute POSIX paths, drive (`C:`) and UNC
  (`\\\\server`) paths, `.`/`..`/empty segments, and segments containing `:`
  (a drive or alternate-stream form on Windows). Glob patterns in
  `repo.payload_globs` stay `/`-only, because they are patterns, not paths.
- **Line endings.** Every rewrite preserves them: a CRLF `.sops.yaml` keeps
  CRLF, a file with no change is written back byte-for-byte, and a payload's
  line endings are sops's to keep (lockset writes values through sops, never as
  a file replace).
- **Keychain.** `--custody keyring` uses `security(1)` on macOS and the OS
  credential store on Linux and Windows. The backend is the default-on
  `keyring` feature; `cargo build --no-default-features` produces a binary for
  targets or images without it, and `--custody keyring` there fails with a
  message naming `env:`/`file:` and the missing feature instead of a compile or
  runtime surprise.
- **Identity types.** `AGE-SECRET-KEY-1…` x25519 identities and `age1…`
  recipients only. Not supported, each with a message that says so: plugin
  identities (`AGE-PLUGIN-…`) and plugin recipients, passphrase-encrypted
  identity files, SSH recipients (`ssh-ed25519 …`), PGP recipients, and
  KMS/GCP/Azure/Vault rules (those rules parse and are reported per rule; only
  `grant`/`revoke` on them refuse).
- **CI.** The portability job builds without the keyring backend and checks the
  Windows, Linux, and macOS targets.

## Configuration

`lockset.toml` at the repository root, when present, carries the repository's
conventions. Every field is optional and takes the value shown; the layers are,
highest first, flags, environment, this file, the defaults.

```toml
[repo]
sops_config = ".sops.yaml"               # the map --repo walks up to (with lockset.toml);
                                         # a non-default path is passed to sops as --config
payload_globs = ["secrets/**/*"]         # which files are payloads
default_payloads = ["secrets/dev.env"]   # what run and set use without --payload

[[identities]]
label = "admin"                          # the registry wins over .sops.yaml comments
public = "age1..."                       # one entry per identity
roles = ["admin"]                        # `admin`: must open every payload

[labels]
admin = "admin"                          # legacy label used while no registry exists
person_prefix = "dev-"                   # suggested for person add

[custody]
kind = "auto"                            # auto | the same forms as --custody
env = "LOCKSET_AGE_KEY"                  # what bare `env` reads
keychain_item = "lockset-age-key"        # what bare `keyring` reads
keychain_account = ""                    # empty: the current user

[codec]
sops = "sops"                            # --sops > LOCKSET_SOPS > this
min_version = "3.13.0"                   # the preflight floor
```

`run` and `set` never invent a payload: without `--payload` they use
`repo.default_payloads`, and a repository that names none stops with exit 2 and
lists the payloads it does have; `set` needs exactly one. A setting's precedence:

| Setting | Flag | Environment | File |
| --- | --- | --- | --- |
| repository root | `--repo` | `LOCKSET_REPO` | walks up from the cwd |
| config file | `--config` | `LOCKSET_CONFIG` | `lockset.toml` at the root |
| sops binary | `--sops` | `LOCKSET_SOPS` | `codec.sops` |
| custody | `--custody` | `LOCKSET_CUSTODY`, then the identity variable | `custody.*` |
| payloads | `--payload` | — | `repo.default_payloads` |

A config error names the file and the field and exits 2, so a typo cannot
quietly change which secrets a pipeline reads.

Discovery walks the repository once, skips symlinks and hidden files, dedupes
canonical paths, and keeps what `repo.payload_globs` matches; the dotenv-only
format check still applies to everything it keeps.

### Custody policy

Custody is chosen in this order, and each layer is explicit about what it
accepts:

1. `--custody <spec>` — the flag wins over everything.
2. `LOCKSET_CUSTODY` — the same grammar in the environment, so a pipeline can
   switch sources without a flag. An empty value counts as unset.
3. The identity variable (`custody.env`, `LOCKSET_AGE_KEY`) when it is set:
   bare `env` custody.
4. `custody.kind` — `auto` (the default), or any spec form. A concrete kind,
   such as `keyring` or `env:DEPLOY_KEY`, applies to non-interactive runs too.
5. `auto` off a terminal means **no identity source**: a container is never
   handed whichever key the keychain happens to hold, and a mutation that needs
   a key fails with `no identity in custody`. On a terminal `auto` uses the
   keychain.

The forms are `env`, `env:<NAME>`, `keyring`, `keyring:<service>`,
`file:<absolute path>`, and `none`. A per-repo keychain item is
`custody.keychain_item` plus `custody.keychain_account` (empty: the current
user); `keyring:<service>` overrides the service and keeps the configured
account. An unknown or incomplete spec exits 2 and lists the forms; nothing
falls back to another source.

```sh
# Two pipelines on one machine, different secret sources
lockset run --custody env:DEPLOY_KEY --payload secrets/prod/deploy.env -- ./deploy
LOCKSET_CUSTODY=env:PLAN_KEY lockset set NEW --payload secrets/dev.env

# A repository with its own keychain item
#   [custody]
#   kind = "keyring"
#   keychain_item = "lockset-age-key-app"
#   keychain_account = "ci"
lockset doctor

# A mounted key on a headless runner
lockset run --custody file:/run/secrets/age-key --payload secrets/dev.env -- ./tool
```

### Labels and the identity registry

The `[[identities]]` entries are the source of truth for labels: `who` lists
them, `grant` requires the identity to be registered, and `revoke --label`
resolves through them. Trailing `# label,...` comments in the sops config are a
**migration input only** once a registry exists: a comment label that conflicts
with the registry (or names a key the registry does not know) is reported as
drift, never silently repaired.

Convert a comment-labelled repository once:

```sh
lockset who --toml >> lockset.toml   # review the block, then commit it
lockset who                          # same labels, now from config
```

The conversion changes no recipients. Every rewrite still keeps what it did not
touch: free-text comments (for example `# admin,recovery (managed by
terraform)`) are preserved verbatim, a label-only comment is regenerated only
when every key still has a label, and line endings are kept. The `admin` role
replaces the `labels.admin` label for the coverage check; the label stays the
fallback for repositories that have not migrated.

### Mixed recipient backends

`sops` rules keyed by another backend (`pgp`, `kms`, `gcp_kms`, `azure_kv`,
`hc_vault_transit_uri`) parse and do not fail the file. `status` lists their
payloads, and `check` reports each such rule on its own line with the backend
and what still works: `rotate` and `set` do, because they need no age
recipients. `grant` and `revoke` refuse only a rule they would have to rewrite —
the message names the rule and the backend and points at `--only` — so the rest
of a mixed map stays manageable.

```sh
lockset --config ./ci/lockset.toml doctor
LOCKSET_REPO=/srv/app lockset status     # no --repo, no cd
lockset --dry-run set NEW --from-env NEW # uses repo.default_payloads
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

Payloads merge in the order given. A key defined by more than one payload is an
error (exit 2) that names the key and both payloads, because a pipeline cannot
tell which value it received: pass `--last-wins` or `--first-wins` to choose. A
payload that defines the same key twice is an error under either flag. The
output is secret material: `export` warns on stderr, so mask values before a
runner echoes them, keep the files it writes out of git, and prefer `run`
whenever one command can consume the values.

## Doctor

`lockset doctor` is the preflight a pipeline runs before touching secrets. It
checks the repository and `.sops.yaml`, that `sops` is present and at least
3.13, which custody is in use and whether it is readable, that only the current
identity sources are read, the identity itself, its coverage, the payloads, the
configured default payloads, and the CI custody policy (a
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

A failing external tool keeps code 4 even when the mutation rolled back
cleanly; a rollback that cannot restore a file is 6. `status --strict` exits 1
on drift, empty values, a missing identity, or
unreadable payloads; without `--strict` it always reports and exits 0. `check`
covers identity presence, unreadable payloads, ciphertext, plaintext, empty
values, label drift, admin coverage, and a decrypt proof for whatever identity
this machine has — no particular label is required.

## Container image

`ghcr.io/yazee-me/lockset` carries the CLI **and** a pinned, checksum-verified
`sops` (3.13.3), so a pipeline needs neither installed. It is built for
`linux/amd64` and `linux/arm64` and runs as the non-root user `10001` with
`/repo` as its working directory and `lockset` as its entrypoint. Tags are
`:<version>`, `:<major.minor>`, and `:latest` (a prerelease gets its version
tag only). Every release records the digest in `image-digest.txt`; pin it:

```sh
# env custody: what a CI job usually wants
docker run --rm -v "$PWD:/repo" -w /repo -e LOCKSET_AGE_KEY \
  ghcr.io/yazee-me/lockset:0.1.0 doctor

docker run --rm -v "$PWD:/repo" -w /repo -e LOCKSET_AGE_KEY \
  ghcr.io/yazee-me/lockset@sha256:<digest from image-digest.txt> \
  run --payload secrets/dev.env -- ./deploy.sh

# file custody: mount the key read-only and run as its owner so mode 0600 is readable
docker run --rm -v "$PWD:/repo" -v /run/secrets:/run/secrets:ro \
  --user "$(id -u):$(id -g)" -w /repo \
  ghcr.io/yazee-me/lockset:0.1.0 --custody file:/run/secrets/age-key doctor
```

Nothing secret is part of the image or its layers: the only key source is what
you mount or pass in the environment. Read-only commands (`status`, `who`,
`check`, `doctor`, `export`, `run`) work with `--read-only`; a mutation needs a
writable repository mount for its lock and the rewritten payloads. Build and
test it locally with `docker build -t lockset .` and
`./scripts/container-smoke.sh lockset` (the script generates a throwaway age
identity, encrypts a payload with the image's sops, then runs `doctor`, `run`,
and file custody, and checks the non-root user and the absence of keys in the
layers).

## Releases

A tag `v<version>` (matching the version in `Cargo.toml`) runs the release
workflow, generated by [cargo-dist](https://axodotdev.github.io/cargo-dist):
it builds the CLI for every supported target, packages it, checksums it, and
publishes a GitHub release.

| Platform | Archive |
| --- | --- |
| Linux x86_64 (gnu and musl) | `lockset-x86_64-unknown-linux-{gnu,musl}.tar.xz` |
| Linux aarch64 (gnu and musl) | `lockset-aarch64-unknown-linux-{gnu,musl}.tar.xz` |
| macOS x86_64 and Apple Silicon | `lockset-{x86_64,aarch64}-apple-darwin.tar.xz` |
| Windows x86_64 | `lockset-x86_64-pc-windows-msvc.zip` |

Every archive ships with `<archive>.sha256`, the release carries a combined
`SHA256SUMS`, and each artifact has a GitHub Artifact Attestation (SLSA
provenance) that `gh attestation verify <file> --repo Yazee-Me/Lockset` checks.
Shell and PowerShell installers are published for each release. The release
body is the matching `CHANGELOG.md` section, so the breaking changes — today the
identity and sops rename — are on the release page; CI fails if that section is
missing them.

Install without Rust:

```sh
# Linux and macOS
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/Yazee-Me/Lockset/releases/latest/download/lockset-installer.sh | sh

# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/Yazee-Me/Lockset/releases/latest/download/lockset-installer.ps1 | iex"
```

**Optional signatures.** Set `MINISIGN_SECRET_KEY` (and `MINISIGN_PASSWORD` for
an encrypted key) and the assets workflow publishes `.minisig` files next to
each archive; check one with
`minisign -Vm <archive> -x <archive>.minisig -P <public key>`. Without the
secret the release is unsigned, but checksums and attestations still cover every
file.

**Homebrew metadata.** cargo-dist can publish a formula, but that needs a
`Yazee-Me/homebrew-tap` repository and a token, so this repository deliberately
does not configure it. To enable it later, add `homebrew` to `installers` and
`tap = "Yazee-Me/homebrew-tap"` in `dist-workspace.toml` once the tap exists.

**Verification on clean runners.** After the release is published,
`.github/workflows/release-assets.yml` re-checks every published checksum,
unpacks the archives, and runs `lockset --version` and `--help` on fresh Linux,
macOS, and Windows runners.

Locally, with `dist` installed (`cargo install cargo-dist` or the installer
script above):

```sh
mise run release:plan     # what a tag would publish (dist plan)
mise run release:build    # the artifacts for this machine
mise run release:verify   # checksums, unpack, run target/distrib
```

## Design notes

- `lockset-core` never spawns a process, reads the environment, or touches the
  filesystem; `lockset-tools` implements the ports. That is what makes the model
  testable without credentials and reusable from another front end.
- The CLI is a thin binary over `lockset::run`: the process environment is
  captured once as `Inputs` and the adapters take it explicitly
  (`SopsCodec::with_environment`, `EnvCustody::with_environment`), so nothing
  below `main` reaches for a global. Output goes through the caller's writers,
  diagnostics through an explicit level (`RUST_LOG` is read from the same
  inputs), and `run_with_context` accepts ports built by the caller.
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
- `run` hands the child its own fate: on Unix the CLI `exec`s the command, so
  the exit code and any terminating signal are the command's own; elsewhere the
  wait status is propagated, with a signal mapped to `128 + signal`. The child
  starts from the parent's environment minus the identity, unless
  `--clean-env` narrows it to `PATH`, `HOME`, `TMPDIR`, and `LANG`.
- `--dry-run` builds the plan before custody is consulted, so every mutating
  command renders its plan with no identity at all and a pipeline can diff a
  change without secrets. The key is required only to apply, and an invalid
  plan keeps its own exit code instead of hiding behind a missing identity.
- Payload discovery skips symlinks and dedupes canonical paths, so a
  self-referential link cannot duplicate or loop the inventory. A payload that
  cannot be read or parsed is a finding with its path and error (`status`,
  `check`), and the remaining payloads are still reported and rotated.
- Sops output reaches the error message whole, not just its first line: a
  failure after several lines of context still names the cause. Redaction runs
  before the text is formatted, so neither the key handed over nor any
  `AGE-SECRET-KEY-…` token sops prints survives into a CI log.
- Writes are durable: the temp file is fsynced before the rename and the parent
  directory after it, and a CRLF `.sops.yaml` is rewritten with CRLF.
- Paths are `PathId` values parsed relative to the repository root, so no
  `Repo` or `Codec` call can be handed a traversal or a value sops would read
  as an option.
- Paths are normalized to `/` when parsed, so a Windows path and a POSIX path
  reach the same `PathId` and the same rule; a rewrite keeps the file's line
  endings (CRLF stays CRLF, and a no-op rewrite is byte-identical).
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
