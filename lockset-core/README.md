# lockset-core

The tool- and OS-agnostic model behind [Lockset](https://github.com/Yazee-Me/Lockset):
`.sops.yaml` parsing and rewriting, payload metadata, plans, reports, and the
ports (`Codec`, `Custody`, `Repo`). It never spawns a process, reads the
environment, or touches the filesystem.

Licensed under MIT or Apache-2.0.
