# Verification report template

Copy this file to `docs/verification/<slug>-<YYYY-MM-DD>.md`. The first fenced JSON block is the machine-readable record the checker validates; the prose below it is for the humans who decide whether to merge. Keep both in sync.

````markdown
# Verification — <change>

- **Artifact:** <branch / commit / PR>
- **Surface tested:** <URL / CLI / app build / job runner>
- **Environment:** <local / staging / production-read-only>
- **Verifier:** output-verifier (<model>)
- **Verdict:** <validated | blocked | unverified | not-applicable>

```json
{
  "change": "<change-slug>",
  "date": "<YYYY-MM-DD>",
  "artifact": "<commit or PR>",
  "surface": "<what was exercised>",
  "environment": "<local|staging|production-read-only>",
  "verdict": "<validated|blocked|unverified|not-applicable>",
  "sources": [
    {
      "id": "S1",
      "kind": "<observed|external|differential|invariant|research|prior|declared>",
      "ref": "<URL, file:line, or endpoint + request>",
      "retrieved": "<YYYY-MM-DD>"
    }
  ],
  "checks": [
    {
      "id": "C1",
      "requirement": "<exact requirement name from the spec>",
      "covers": ["<extra requirement names this probe covers, optional>"],
      "origin": ["S1"],
      "probe": "<exact command or UI steps>",
      "expected": "<observable outcome, independent of the spec's wording>",
      "observed": "<trimmed actual response/state>",
      "flip": {
        "perturbation": "<what was changed and how>",
        "observed": "<what the probe did while the rule was wrong>",
        "result": "<pass|fail>"
      },
      "verdict": "<validated|corroborated|spec-echo|contradicted|unverified|not-applicable>",
      "reason": "<required for unverified/not-applicable, optional elsewhere>"
    }
  ],
  "rule_trace": [
    {
      "rule": "<threshold, date rule, authorization rule, state transition>",
      "enforcement": ["<path:line>"],
      "duplicated_literals": ["<path:line = value>"],
      "entry_points_tested": ["<API route / UI action / job / webhook>"]
    }
  ],
  "circularity": [
    {
      "finding": "<what makes the evidence self-referential>",
      "evidence": "<quote or path:line>",
      "severity": "<high|medium|low>"
    }
  ],
  "gaps": ["<unresolved question, owner, and why it does not block>"]
}
```

## What each check must contain

- **Independent origin.** `origin` must include at least one source whose `kind` is not `declared`.
- **A real probe.** The exact command or user steps, plus the observed output. A code citation is not a probe.
- **A flip.** For `validated`, the rule was made wrong and the probe reported it. `result: pass` means "the probe detected the perturbation"; `fail` means it did not, and the check cannot be `validated`.
- **Coverage.** Every requirement in the spec appears as a `requirement` or in some check's `covers`. Requirements under `## REMOVED Requirements` still need a check (the removal is observable).

## Verdict meanings

| Verdict | Meaning |
|---|---|
| `validated` | Independent origin, black-box probe, and a passing flip. |
| `corroborated` | Independent origin and a real probe, but no safe falsification. Weaker evidence; state why. |
| `spec-echo` | The only origin is the declared rule, or the flip failed. Blocks. |
| `contradicted` | The artifact disagrees with an independent oracle. Blocks; the rule or the code is wrong. |
| `unverified` | The oracle or probe could not be obtained. Blocks until an owner resolves it. |
| `not-applicable` | No observable behaviour changed. Requires a reason. |

## Rule trace (fill this, do not skip it)

Checking behaviour is not enough if the rule is transcribed as special cases. For each declared threshold, date computation, authorization rule, and state transition:

- name the single enforcement point, or every point if the rule is genuinely enforced in several layers
- list duplicated literals outside that point
- list every entry point exercised (API, UI, job, webhook, direct DB)
- state whether a direct database write or a second client can violate the rule

## Circularity audit

Record the evidence that would make the result pass without proving anything:

- tests that assert internal calls or mocks of the unit under test
- expected values computed by the same helper/constant as production
- expectations copied from the spec's examples with no external source
- scenario values hardcoded in production code
- a green suite that stays green when the rule is disabled

## Recommendation

One paragraph: merge, fix, or return to discovery. Name the exact blocker and the owner.
````
