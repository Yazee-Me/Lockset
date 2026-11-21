# Use Lockset

Run from the repository, or pass `--repo <dir>`.

## Read-only

```sh
lockset status                 # identity, payloads, coverage, empty values, drift
lockset status --strict        # exit 1 on any finding
lockset who                    # labels, public keys, payload counts
lockset check                  # invariants without a key, plus decrypt verification
lockset doctor                 # preflight, including the CI custody policy
```

`status`, `who`, `check`, and `doctor` accept `--json`; every document carries
`schema_version: 1` and no secret values.

## Write one value

```sh
lockset set NEW_KEY --payload secrets/dev.env          # hidden prompt on a terminal
lockset set NEW_KEY --payload secrets/dev.env --stdin
lockset set NEW_KEY --payload secrets/dev.env --from-env NEW_KEY
lockset set NEW_KEY --payload secrets/dev.env --value-file /run/secrets/new-key
lockset set NEW_KEY --payload secrets/dev.env --from-env NEW_KEY --if-absent
lockset --dry-run --json set NEW_KEY --payload secrets/dev.env
```

Off a terminal, `set` needs one of `--stdin`, `--from-env`, or `--value-file`.
An empty value is refused unless `--allow-empty` is passed. There are no
silent defaults.

## Run a command with the payload

```sh
lockset run --payload secrets/dev.env -- ./deploy.sh
lockset run --payload secrets/a.env --payload secrets/b.env --last-wins -- ./tool
lockset run --payload secrets/dev.env --clean-env -- ./tool   # only PATH, HOME, TMPDIR, LANG
lockset run --payload secrets/dev.env --pass-custody -- ./tool # deliberate exception
```

`run` puts the payload values in the child's environment and strips the
identity. The child's exit code and signals are passed through. `--clean-env`
starts from a minimal environment; `--pass-custody` deliberately gives the
child the identity environment and needs a reason.

## Export for a pipeline

```sh
lockset export --payload secrets/prod/deploy.env --format dotenv
lockset export --payload secrets/prod/deploy.env --format json
lockset export --payload secrets/prod/deploy.env --format sh
```

Exported values are secret material. In GitHub Actions, mask each value before
writing it to `$GITHUB_ENV`; the composite action does that for
`export-env: "true"`.

## People and keys

```sh
lockset person add age1... --label dev-alice
lockset person remove --label dev-alice
lockset grant age1... --label dev-alice      # add a recipient, re-wrap payloads
lockset revoke --label dev-alice             # remove, re-wrap, rotate the data key
lockset rotate --payload secrets/dev.env     # rotate the data key only
lockset key status
lockset key forget
```

A machine cannot revoke its own identity without `--force`; decommission it
from another admin machine. Revoking a recipient rotates the data key but
cannot erase ciphertext already in git history.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | ok |
| 1 | findings: failed `check`, `status --strict`, or runtime failure |
| 2 | usage or configuration: bad argument/path, invalid `lockset.toml`, unknown custody, no `.sops.yaml`, unsupported payload |
| 3 | custody or authentication: no identity, keychain or file custody failure |
| 4 | external tool: `sops` missing or failing |
| 5 | conflict or lock: input changed or another process holds the lock |
| 6 | partial apply: a mutation could not be undone; the message names the files |

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `no .sops.yaml or lockset.toml found` | `cd` into the repository, or pass `--repo` |
| `no identity in custody` | `lockset key status`; set `LOCKSET_AGE_KEY`, `--custody`, or the keychain |
| `sops` missing or too old | `sops --version`; need 3.13+, or pass `--sops`/`LOCKSET_SOPS` |
| payload reported as unsupported | Only dotenv `.env` is a payload; hidden files are skipped |
| lock conflict (exit 5) | Another lockset is writing; retry after it finishes or raise `--lock-timeout` |
| drift between map and payloads | `lockset status`; re-wrap with `grant`/`revoke`, or inspect the named payloads |

Never print a decrypted value to a log or commit it. A failing sops call keeps
its stderr, with the identity replaced by `[redacted]`.
