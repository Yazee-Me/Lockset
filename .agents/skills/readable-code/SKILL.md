---
name: readable-code
description: >
  Write and check code for human readability — code a developer can grasp at a
  glance, top to bottom, without backtracking or re-reading. Use whenever the
  user is writing, adding, refactoring, or reviewing code and cares that it be
  easily understood; whenever they say "readable", "clean", "clear",
  "self-documenting", "maintainable", "easy to understand", "can't tell what
  this does", "this is hard to read", or ask you to check, review, clean up,
  or improve how readable some code is. Applies to any programming language.
---

# Readable code

Readability is a property of the **reader**, not the writer. Code is readable
when a competent developer unfamiliar with it — including your future self,
paged at 3am — can understand what it does and why, top to bottom, without
re-reading or holding a map in their head.

Two jobs:
1. **Write** — code comes out readable the first time.
2. **Check** — audit existing code and fix the readability problems.

## The core move: read it as a stranger

You cannot judge readability while holding the writer's mental model. Before
touching anything, deliberately re-derive the code's meaning from the text
alone, as if you've never seen it. Every place you had to stop, re-read, or
guess is a readability defect. Name it, then fix it.

That is the whole skill in one sentence: **trace the flow as a stranger;
every stop, re-read, or guess is a bug.**

## The ladder: rename → reorder → extract → comment

Fix defects in this order — cheapest, highest-leverage first:

1. **Rename.** The single highest-leverage fix. A name says what the thing
   *is* or *does*, not how or when it was written. If no honest name comes,
   the design is murky — fix the design; don't reach for a comment.

   Rename only what *you* own: local variables, parameters, private helpers,
   and internal function names. Leave untouched what a caller passes in or
   receives back — the keys of input/output dicts, JSON/wire field names, DB
   columns, and public API signatures. Those are the caller's contract;
   renaming them changes behaviour, not readability. If a caller's key is
   cryptic (`'st'`), document it in a docstring or map it to a clearer local
   name — never rename the key itself.
2. **Reorder.** Intent before detail. The reader meets the *what* before the
   *how*. Read a function top to bottom: does it answer questions in the order
   the reader asks them?
3. **Extract.** A block whose purpose you had to work out — pull it into a
   named function. The function's name *is* the comment.
4. **Comment.** Last resort, and only the "why" the code can't express:
   intent, constraints, a non-obvious reason. Delete comments that restate the
   code — a comment duplicating the code is a lie waiting to happen.

## The checklist

Apply while writing; hunt for violations while checking:

- **Names reveal intent.** `timeoutMs` over `t`; `retryOrGiveUp` over
  `doStuff`. A reader should never need a name's definition to know its
  meaning. Name booleans as questions (`isValid`, `hasExpired`).
- **One job per function.** A function is a summary of its body — if the name
  needs "and" or "or", split it.
- **Local reasoning.** A reader understands a function without tracking
  distant state. Avoid long functions, deep nesting (flatten with early
  returns / guard clauses), and variables whose value changes far from use.
- **Explicitness over cleverness.** Prefer the obvious construct over the
  clever one. A slightly longer, obvious solution beats a shorter puzzle: the
  reader pays for cleverness every read, you pay for the obvious once.
- **Signatures tell the contract.** Parameter names, return types, and
  defaults let a reader use the function without opening its body.
- **Magic numbers get names.** A bare `7`, `86400`, or regex becomes a named
  constant whose name explains *what* it is, unless the meaning is
  self-evident.
- **One idiom per concept.** If the codebase names one thing two ways, or
  formats the same construct two ways, pick one and use it — a reader learns
  a pattern once.
- **Comments earn their place.** See the ladder's step 4.

## Writing mode

Apply the checklist as you write. Before you call a hunk done, run the
stranger test once on the finished code, not the draft. Fix what fails.
Proportion effort to how often and how hard the code will be read: a hot,
complex path earns more polish than a one-off script.

## Check mode

When asked to check or review readability:

1. **Scope** the code — the file, function, or diff the user points at. Don't
   wander into adjacent untouched code.
2. **Stranger-test** it: read top to bottom, note every stop / re-read / guess.
3. **Fix** via the ladder — rename only identifiers you own (see the ladder),
   and keep behaviour identical for every change.
4. **Verify** behaviour is unchanged — readability edits must not change what
   the code does. Run the existing tests or a smoke check. (In writing mode
   this is automatic: you're building it.)

If the user wants only a *report* of problems, list them (dimension + fix)
instead of editing. If they want edits, edit and note the notable changes and
why — one line each, no essays.

## Boundaries

- **Not simplicity.** `ponytail` minimizes ("smallest thing that works"); this
  skill maximizes comprehension. They usually pull together, but a clever
  one-liner is minimal yet unreadable, and a long obvious function is readable
  yet not minimal. Different questions — pair them, don't merge them.
- **Not spec/standards review.** `code-review` checks a *diff* against repo
  standards and the originating spec. This skill reads any code for
  comprehension, standalone.
- **Not architecture.** `codebase-design` / `domain-modeling` handle module
  seams and domain vocabulary. This skill works at line-to-function level; if
  a readability defect keeps coming from a bad seam, note it and hand off
  rather than paper over it.
- **Don't churn.** When fixing a bug or adding a feature, make the *touched*
  code readable as you go — don't refactor untouched code, and don't rename
  public APIs without checking their callers first.
