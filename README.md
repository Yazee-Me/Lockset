# Lockset

Repository secrets with a small, boring surface: per-principal grants on top of
sops and age. Lockset is a CLI and a Rust library. sops stays the codec and
`.sops.yaml` stays the recipient map — there is no Lockset server and no second
secret store.

## What it does

- Reports who may read what, and drift between the map and the payloads:
  `status`, `who`, `check`.
- Runs a command with one or more payloads in its environment: `run`.
- Sets a single value and reads it back to prove it landed: `set`.
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
  `lockset-age-key`, or an explicit `--custody file:<path>`.
- A repository with `.sops.yaml` at its root, payloads as `secrets/**/*.env`,
  and recipients labelled by a trailing `# label,...` comment in recipient
  order.

## Use

```sh
cargo install --path lockset --locked

lockset status                       # identity, payloads, coverage, drift, empty values
lockset who                          # label -> public key, payload count, local key
lockset run --payload secrets/dev.env -- ./my-command
lockset set NEW_KEY --payload secrets/dev.env
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
- Rewrites touch only the `age:` line of `.sops.yaml` and are followed by a
  decrypt, because a structurally valid file with lost values only shows up on
  read.

## Security notes

- Values are never written to a file: `run` passes them through the child
  environment, which same-user processes can read. Treat a machine that runs
  this as trusted.
- The private key reaches sops through the child environment
  (`SOPS_AGE_KEY`), never through argv.
- Revoking a recipient rotates the data key, which bounds future exposure. It
  cannot erase ciphertext already in git history or plaintext already copied.

## Provenance

Imported from `Yazee-Me/Servers` at commit `e6be297`, where the workspace lived
under `tools/secrets`. Product decision and ticket: `LOC-1`.
