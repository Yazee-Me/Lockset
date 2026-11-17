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

- `sops` 3.13 or newer on `PATH` (override with `LOCKSET_SOPS`).
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

## Use

```sh
cargo install --path lockset --locked

lockset status                       # identity, payloads, coverage, drift, empty values
lockset who                          # label -> public key, payload count, local key
lockset run --payload secrets/dev.env -- ./my-command
lockset run --pass-custody -- ./tool  # deliberate exception: the child gets the identity environment
lockset set NEW_KEY --payload secrets/dev.env      # hidden prompt
printf '%s' "$NEW_KEY" | lockset set NEW_KEY --payload secrets/dev.env --stdin
lockset set NEW_KEY --payload secrets/dev.env --from-env NEW_KEY
lockset set NEW_KEY --payload secrets/dev.env --value-file /run/secrets/new-key
lockset --dry-run --json set NEW_KEY --payload secrets/dev.env   # plan as JSON, value redacted
lockset grant age1... --label dev-alice
```

With mise (pinned toolchain):

```sh
mise install
mise run test        # cargo test --workspace
mise run build       # release build of the CLI
mise run install     # link target/release/lockset into ~/.local/bin
```

## Design notes

- `lockset-core` never spawns a process, reads the environment, or touches the
  filesystem; `lockset-tools` implements the ports. That is what makes the model
  testable without credentials and reusable from another front end.
- Plans are data (`Change` values) and `exec::apply` is the only place
  mutations happen, so `--dry-run` and tests share one path.
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
- Revoking a recipient rotates the data key, which bounds future exposure. It
  cannot erase ciphertext already in git history or plaintext already copied.

## Provenance

Imported from `Yazee-Me/Servers` at commit `e6be297`, where the workspace lived
under `tools/secrets`. Product decision and ticket: `LOC-1`.
