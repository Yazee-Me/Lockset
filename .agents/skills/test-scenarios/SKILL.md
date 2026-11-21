---
name: test-scenarios
description: Cover code you just wrote with test scenarios that go red. Use whenever an implementation is about to be called finished — a feature, a bug fix, or a refactor — even if nobody mentioned tests: the change is not done until every behavior it introduces has a scenario that fails without it, and you have watched it fail. Also use when asked to add tests to existing code, to cover or verify a change, or to backfill scenarios. For writing the test before the code, see the tdd skill.
---

# Test scenarios for new code

New code is finished when something can go red because of it — and stays able to. Two properties make a scenario real: **it lives in the repo**, and **you have watched it fail**. A scenario that only ever passed is decoration: it passes the day it is written, keeps passing after the behavior breaks, and its green light tells the next reader nothing. A harness you deleted told the truth once, then took it with it.

This is the coverage step for code that already exists. The `tdd` skill covers the other direction — the scenario before the code. Everything here still applies once you arrive there.

## 1. Run the suite before writing anything

Completion: you have run the tests nearest your change, and you know the command.

Find the runner the repo already uses and use it — package manifest scripts and devDependencies, the test config at the app root, CI workflow steps, build-tool tasks. Open the existing test file nearest the code you changed and match your neighbours: same directory, naming, assertion style, helpers, and the same way of faking the outside world. A second convention is a tax on everyone who follows you.

Running first also gives you the baseline. A test that was already red before your change is yours to explain now, not later when it is indistinguishable from one you caused.

## 2. Choose scenarios by risk

Completion: every behavior the change introduces has a scenario — or you can say why it does not.

The code already exists, so the seam is fixed: test what the change exposes to its callers — the exported function, the HTTP route, the rendered output — not the private steps it takes to get there. Behavior a caller can observe survives a rewrite; anything reaching inside does not.

Ask of the change: what breaks, who notices, how badly? Spend scenarios where the answer is worst:

- the new behavior, one scenario each, named after the behavior, so a failure reads like a bug report rather than a line number
- boundaries, where bugs live: empty, zero, exactly at the limit and one past it, absent, duplicate, wrong role or type
- the combinations and the order the code branches on
- the failure path the caller handles — assert the specific error, not that something threw

What does not earn a scenario: what the framework or type system already guarantees, a pass-through, a constant, a rename. Line coverage is not the target; the set that a realistic mistake in this area would trip is.

## 3. Make each scenario go red

Completion: every new scenario has failed in front of you, and passes with the code restored.

This is the skill. Break the code in the one way that scenario exists to catch — flip the condition, move the boundary by one, return the other branch, drop the field — run, watch it fail, restore. A scenario that stays green while the code is wrong tests nothing; keep editing it until it goes red. One edit and one run per scenario is the whole cost, and it is the only evidence that the green you are about to report means anything.

A throwaway harness is good scaffolding for this — the pre-change implementation copied beside the new one, the running app driven by hand — but it is scaffolding, not the deliverable. The scenario that lands in the repo has to stand on its own after you are gone.

Expected values come from outside the code: a literal you worked out by hand, the spec, a known-good example. An expectation produced by re-running the code's own logic inside the test can never disagree with the code, which makes it worthless as a check.

## 4. Existing scenarios your change turned red

Completion: every red is resolved deliberately, and the resolution is in your report.

A test that was green before your change and red after is a decision, not an obstacle:

- **the behavior change is intended** — the scenario encodes the old contract; rewrite it against the new one and say so, because a reviewer needs to see the contract move
- **the behavior change is not intended** — the code is wrong, however reasonable it looked

Resolve each red by changing the code or by deliberately moving the contract. Weakening an assertion — loosening an expected value, widening a range, deleting the case — converts a caught bug into a blind spot that every future reader will trust.

## 5. Claiming coverage

Completion: every coverage claim you make names a scenario and the file holding it, and you have opened that file.

"This is already covered" is the sentence that rots fastest, because it is written from memory and read as fact. A module no test file imports is not covered, however obvious its behavior looks. Before making the claim, open the file and confirm it imports and exercises the thing you are claiming — especially when the alternative is writing the scenario you just talked yourself out of.

## 6. When the surface has no suite

Completion: the gap is reported, and any framework setup was approved first.

Choosing a framework, a config and a CI step outlives your change and belongs to whoever owns the repo, so report what is missing and what you would set up — and verify the change the cheap way meanwhile: run the real program, drive it, script against its surface. If you are asked to set the suite up, do that, then start again at step 1.

## 7. Report

Completion: a reader can run the scenarios and knows what is not covered.

- the command that runs them
- the scenarios added, each with the file it lives in
- what you left uncovered and why — needs a database, needs a browser, throwaway
- contract changes, from step 4

Leave scenarios you did not touch alone: no reformatting, no renaming, no restructuring, so the diff stays about the change.

None of this applies to edits with nothing to observe: documentation, comments, a config value, a throwaway spike.
