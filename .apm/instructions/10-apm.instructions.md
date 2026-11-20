---
description: "APM-managed agent context workflow"
applyTo: "**"
---

## Agent context

- The shared source is `Yazee-Me/Playbook`, pinned in `apm.yml`.
  `apm.lock.yaml` records the resolved commit and the content hashes.
- `AGENTS.md` and `.agents/skills/` are generated. Never edit them by hand;
  edit `.apm/instructions/` or Playbook.
- `apm.yml` targets `opencode`, whose output is exactly `AGENTS.md` plus
  `.agents/skills/` — the same surface every harness reads, so no per-client
  directory carries context. `.opencode/` stays empty until an agent or prompt
  primitive is added.
- A fresh clone or worktree has no `apm_modules/`. Run `apm install --frozen`
  before `apm compile`; otherwise compile omits the shared Playbook
  instructions.
- `mise run agent:sync` resolves the package and regenerates the context files.
- `mise run agent:check` verifies the committed output against the lockfile and
  Playbook, then runs `apm audit --ci`. Run it before a commit or pull request.
- `mise run agent:latest` compares the pin with the newest Playbook tag;
  `mise run agent:upgrade [version]` moves the pin and regenerates the context.
- `apm_modules/` is generated and gitignored.
