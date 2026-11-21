# Configure a repository

Lockset has no `init` command. Bootstrap with sops once: the map, the first
encrypted payload, and an age identity are the whole setup.

## 1. Create an identity

Keep it outside the repository, with mode 0600:

```sh
mkdir -p ~/.config/lockset
age-keygen -o ~/.config/lockset/age-key.txt
```

The file prints the public `age1...` recipient in a comment. Store the private
key in custody:

```sh
# macOS/Linux keychain; macOS prompts for keychain access
lockset key import --file ~/.config/lockset/age-key.txt

# or environment custody
export LOCKSET_AGE_KEY="$(grep '^AGE-SECRET-KEY-' ~/.config/lockset/age-key.txt)"

# or an absolute file outside the repository
export LOCKSET_CUSTODY="file:/run/secrets/age-key"
```

Never commit the identity, never pass it as an argument, and never put it in a
payload.

## 2. Map recipients

`.sops.yaml` at the repository root:

```yaml
creation_rules:
  - path_regex: secrets/.*\.env$
    age: age1... # admin
```

The trailing `# admin,...` comment labels recipients in order and is how
Lockset reports coverage on a repository that has not moved to the
`[[identities]]` registry. For several recipients, separate the keys and the
labels with commas:

```yaml
    age: age1...,age1... # admin,dev-alice
```

Public keys only. A committed `.sops.yaml` never contains a private key.

## 3. Create the first payload

Payloads are dotenv files matched by `secrets/**/*` by default. Create one with
sops, because `lockset set` edits an existing payload:

```sh
mkdir -p secrets
printf 'BOOTSTRAP=1\n' > secrets/dev.env
sops --encrypt --in-place secrets/dev.env
```

`sops` reads `.sops.yaml`, so the new payload has the recipients above. Check
that it contains `ENC[` rather than plaintext.

## 4. Optional: `lockset.toml`

Every field is optional. The useful minimum:

```toml
[repo]
payload_globs = ["secrets/**/*"]
default_payloads = ["secrets/dev.env"]

[custody]
kind = "auto"                 # or env, env:NAME, keyring, keyring:service, file:/abs/path, none
env = "LOCKSET_AGE_KEY"
keychain_item = "lockset-age-key"
```

Precedence, highest first: flags, environment, `lockset.toml`, defaults.
`repo.default_payloads` lets `run` and `set` omit `--payload`; `set` needs
exactly one default.

For a label registry instead of comments:

```sh
lockset who --toml >> lockset.toml   # review and commit the [[identities]] block
```

The registry then wins over `.sops.yaml` comments; conflicts are reported as
drift.

## 5. Verify

```sh
lockset doctor          # repo, sops, custody, identity, coverage, payloads, CI policy
lockset status          # identity, payloads, recipients, empty values, drift
lockset who             # label -> public key, payload count, whether it is local
```

`doctor` exits 1 and names every failing check. Do not proceed until it passes.

## Custody rules

| Form | Use |
| --- | --- |
| `keyring[:service]` | A developer machine with an OS keychain |
| `env[:NAME]` | CI or a terminal session; default variable `LOCKSET_AGE_KEY` |
| `file:/absolute/path` | A mounted secret such as `/run/secrets/age-key`; must be outside the repository, regular, and not group/world readable |
| `none` | Read-only commands without an identity |

A non-interactive run never falls back to the keychain implicitly. It reports
no identity unless `LOCKSET_AGE_KEY`, `--custody`, `LOCKSET_CUSTODY`, or
`lockset.toml` selects one. `auto` does not use the keychain off a terminal.
