---
name: verify-output
description: Verify an implemented feature against an oracle that is independent of the declared business rules, so a passing result cannot be a restatement of the spec. Use after implementation and before merge or archive, or before coding to derive acceptance oracles from research and external sources. Triggers on "verify the output", "validate this feature", "is this just the spec", "independent acceptance", "did we build the right thing".
---

# Verify Output

The failure this prevents: **spec → code → tests**, all produced from the same declared rules. The implementation can be internally consistent, the tests green, and the result still wrong, because the only source of truth was the rule being checked. A check whose expected value comes from the change's own spec is not evidence; it is an echo.

Verification means proving the behaviour is correct **for a reason that did not come from the declared rules**.

## Modes

- **pre** — derive the oracle table before writing the spec or code. Read research, regulations, competitors, existing product behaviour, and prior art. Do not read the planned implementation. Write `docs/verification/<slug>-oracle.md`.
- **post** (default) — verify the built artifact. Delegate to the `output-verifier` agent so the verifying context never saw the implementation conversation.

Invocation: `/verify-output <change | PR | path> [--pre] [--surface <url>] [--run <command>]`.

## Hard rules

1. **Declared-only is a failure.** An expectation whose only source is the change's `spec.md`, ticket, proposal, or the implementer's summary is `spec-echo`, whatever the probe returns.
2. **`validated` needs a flip.** Independent origin + a real probe + a falsification step: perturb the rule and watch the probe go red, then restore. A probe that cannot fail is not evidence.
3. **Observed beats asserted.** Run the artifact. "The tests pass" is not an observation; tests can be derived from the same spec.
4. **Never edit application code or its tests.** Only the report and a throwaway scratch directory. Restore every perturbation.
5. **No production mutation.** Falsify in local, test, or staging. If only production is reachable, do not perturb it; downgrade the check to `corroborated` and say why.
6. **A contradiction indicts the rule, not the oracle.** If reality disagrees with the declared rule, report the rule as the defect. Do not tune the oracle until it agrees.
7. **One requirement, one check.** A check may cover several only when it exercises the same observable behaviour through the same surface.
8. **Record provenance.** Every source has an id, a kind, and a stable reference (URL, file path + line, endpoint + request). No anonymous "industry practice".

## Oracle independence, ranked

Prefer the top. A lower kind never upgrades a higher contradiction.

| Kind | Source | Examples |
|---|---|---|
| `observed` | The running system or real data | staging response, production read, database invariant, log |
| `external` | An authority that owns the fact | law, regulation, standard, vendor API doc, payment-network rule |
| `differential` | A second independent implementation | previous release, competitor endpoint, spreadsheet model, hand calculation |
| `invariant` | A property that must hold regardless of policy | conservation of money, idempotency, ordering, authorization boundary |
| `research` | Stored market/domain evidence | `docs/research/<slug>.md`, interviews, paid-pilot notes, teardown |
| `prior` | A commitment made before this change | committed spec, ADR, published API contract, migration constraint |
| `declared` | This change's rules | proposal, spec scenarios, ticket body, implementer's claim |

`prior` is independent of the current change but still a rule. Use it to detect drift, not as proof that the current rule is right.

## Protocol (post)

### 0. Intake

Collect: artifact path or PR/commit, spec path(s), research record, repository root, run command, surface (URL/CLI/UI), environment, report path. Ask only for what cannot be found. If there is no runnable surface, say so and use the strongest available oracle; do not pretend a code read is an observation.

### 1. Seal the oracle

**Before reading the diff or any test**, read in this order:

1. `docs/research/<slug>.md` and any linked validation notes.
2. External sources the rule depends on: law, standard, vendor doc, competitor behaviour.
3. Committed ADRs, prior specs, API contracts, migration history.
4. The running product: current behaviour, real records, existing endpoints.

Write the expected behaviour for each rule, its origin kind/id, and its **falsifier** ("this is wrong if I observe X"). Requirements with no independent origin are marked `assumption` and cannot become `validated` later.

### 2. Enumerate the declared rules

Extract every `### Requirement:` and its scenarios from the change spec. This list defines coverage, not expected values. A scenario's literal example is not an oracle.

### 3. Probe the public surface

For each requirement, exercise the real entry point: HTTP, UI, CLI, job, webhook. Prefer the highest seam (public API/UI) over unit internals. Record the exact command and a trimmed observed response. A probe that bypasses the authorization boundary, the queue, or the database constraint does not prove the system enforces the rule.

### 4. Generalize beyond the examples

The spec lists the cases the author thought of. Add probes the author did not:

- numeric/date boundaries: 0, 1, max, max ± 1, empty, negative
- time: month end, leap day, DST, working days vs calendar days, timezone
- identity/authorization: another tenant, another user, a removed role, an expired token
- delivery: duplicate request, retry, concurrent request, partial failure, replay
- state: stale version, soft-deleted row, already-processed event
- money: rounding, currency, proration, refund, negative amount

At least three probes must not appear in the spec's scenarios.

### 5. Falsify the rule

For every numeric threshold, date rule, authorization rule, or state transition, make the rule wrong and confirm the probe notices:

- change the threshold/flag/config in a local run
- seed a record one unit past the boundary
- bypass the application layer with a direct database write
- inject a clock, stale payload, duplicate event, or failing dependency
- run the previous release or a competitor endpoint as a differential oracle

Record perturbation, before/after observation, and restoration. If a safe flip is impossible, the check is `corroborated`, not `validated`.

### 6. Audit the derivation (rule trace)

This is the second half of "not derived from the rules": the implementation must enforce the rule generally, not transcribe the spec's examples.

For each numeric or categorical rule, find its enforcement point(s) with `rg`. Flag:

- the same literal repeated in more than one place
- enforcement only in the UI, only in the API, or only in a client, with another entry point unguarded
- a database constraint missing where bypassing the API would violate the rule
- hardcoded scenario values, IDs, or names in production code
- a test that computes expected values with the same helper or constant as production
- a test that mocks the unit under test and asserts the mock was called
- dead branches or feature flags that make the declared rule unreachable

### 7. Write and check the report

Write `docs/verification/<slug>-<YYYY-MM-DD>.md` using [the template](references/report-template.md). Then run the mechanical gate:

```bash
node .agents/skills/verify-output/scripts/check-report.mjs --spec <spec> <report>
```

The checker rejects: missing requirements, `validated` checks without an independent origin or a passing flip, `spec-echo`/`contradicted` verdicts hidden behind an overall pass, high-severity circularity, and malformed provenance.

### 8. Verdict

- `validated` — every requirement has an independent check, at least one real flip, no unresolved high-severity circularity.
- `blocked` — any `spec-echo`, `contradicted`, missing requirement, failed flip, or high-severity circularity.
- `unverified` — the oracle or the probe is unavailable. Name the missing source and who can supply it.
- `not-applicable` — no observable behaviour changed (pure docs/tooling). State what was checked instead.

Report the verdict and exact blockers. Do not merge or archive on a `blocked` report.

## Delegation payload

Do not verify in the context that wrote the code. Spawn `output-verifier` with:

- repository root and artifact (branch/commit/PR)
- spec path(s) and research record path
- run command, surface, environment, test credentials location
- report path
- the pre tooling: "Read `skill://verify-output` first and follow the protocol."

The agent starts blank. Give it facts, not conclusions: no "the implementation looks correct", no summary of what the code does.

## Pre mode

Before implementation, produce `docs/verification/<slug>-oracle.md`:

- one row per intended behaviour: observable, origin kind/ref, how to observe, what would prove it wrong
- the declared-rule coverage map is empty at this point; the oracle is the input to the spec, not its output
- hand the file to the spec author. Requirements that cannot cite an oracle row are written as explicit `assumption` with an owner and a review date

This is how the loop avoids circularity by construction: the spec is written *to* the oracle, not verified *by* itself.
