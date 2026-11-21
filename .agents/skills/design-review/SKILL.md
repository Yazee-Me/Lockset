---
name: design-review
description: >
  Review a class, file, module, or function for design quality through the lens
  of SOLID, classic OOP principles (encapsulation, composition over inheritance,
  Tell-Don't-Ask, Law of Demeter), and the GoF design patterns — then produce a
  prioritized, principle-tagged report of concrete, read-only improvement
  suggestions. Use whenever the user asks to review, critique, improve, refactor,
  or clean up the *design* or *structure* of some code; whenever they mention
  "design patterns", "SOLID", "OOP", "single responsibility", "dependency
  inversion", "inheritance vs composition", "code smell", or want a code review
  focused on class and object design rather than style, readability, or spec
  conformance. Even when the user just says "review this class" or "improve this
  code", consider this skill if the concern is design quality.
---

# Design review

Review a single unit of code — a class, file, module, or function the user
points at — for *design quality*, and propose improvements. You report; the
user decides. Do not edit the code. If the user later asks you to apply a
specific finding you named, apply only the ones they picked.

For a bare function or script (no classes), the lens still applies, but the
class-oriented letters don't: LSP and ISP need a type hierarchy. Judge a
function by SRP (one job), DIP (accept dependencies, don't construct them), and
Tell-Don't-Ask (don't reach into the data you were passed).

## The lens

Three things to check, in this order of leverage:

1. **SOLID** — five principles about how classes take responsibility, vary, and
   depend on each other.
2. **OOP principles** — encapsulation, composition over inheritance,
   Tell-Don't-Ask, Law of Demeter.
3. **Design patterns** — the GoF patterns, used as *remedies for problems you
   found*, never as goals.

## The core move: name the problem, then the pattern

The single most common failure of "design pattern" reviews is
**pattern-hammering**: deciding a pattern is desirable, then hunting for a place
to bolt it on. The result is over-engineered code that's harder to change than
what it replaced.

Work the other way. Read the code and ask: *what is expensive here* — what's
hard to change, extend, test, or reason about? Name the specific principle being
violated ("this class changes for three unrelated reasons"), then ask whether a
pattern is the *natural* remedy. If no pattern fits cleanly, the finding is
still valid: the fix is just a smaller, plain refactor. "No pattern needed" is a
legitimate and often correct conclusion.

## Process

1. **Scope the unit.** Review exactly what the user named — the class, file,
   module, or function. Don't wander into adjacent code; if a real problem lives
   elsewhere, note it under "Not reviewed" rather than fixing it here.
2. **Read it whole first.** Understand what the code does and why before judging
   it. Some apparent smells are justified by context — performance, framework
   constraints, a deliberate choice. Verify the context doesn't already explain
   the thing before you report it.
3. **Work the checklist** below. For every candidate finding, identify the
   concrete future pain it causes, not just the principle it violates.
4. **Write the report** in the exact format below.

## The checklist

### SOLID

- **S — Single Responsibility.** A class has one reason to change. *Symptom:*
  the class's name needs an "and" to describe it; its methods don't share state;
  unrelated feature changes keep touching the same file. *Fix:* split into
  cohesive units, each with one job.
- **O — Open/Closed.** Open for extension, closed for modification. *Symptom:*
  adding a new variant means editing an existing method or type — a `switch`/
  `if`-cascade on a type, or a method that grows a branch per case. *Fix:*
  introduce a seam — polymorphism, Strategy, a pluggable registry — so new
  behaviour is *added*, not *edited*.
- **L — Liskov Substitution.** A subtype must be usable anywhere its base is,
  without the caller noticing. *Symptom:* a subclass throws "not supported",
  no-ops an inherited method, rejects inputs the base accepts, or weakens what
  the base promises; `isinstance` checks special-case a subclass. *Fix:* if
  substitutability doesn't hold, the inheritance is wrong — drop it and compose.
- **I — Interface Segregation.** No client should depend on methods it doesn't
  use. *Symptom:* one fat interface/ABC with unrelated methods; implementers
  throw for the ones they don't support; a caller imports the whole interface to
  use one method. *Fix:* split into smaller, role-specific interfaces.
- **D — Dependency Inversion.** High-level policy shouldn't depend on low-level
  detail; both should depend on an abstraction. *Symptom:* a class constructs its
  own dependencies (`new`/import of a concrete type) where that dependency varies
  or needs swapping for tests. *Fix:* depend on an abstraction, inject the
  concrete instance.

### OOP principles

- **Encapsulation.** Expose behaviour, hide state. *Symptom:* public fields, or
  getters/setters that merely hand out internals, and callers reaching into
  `obj.inner.field`. *Fix:* move the behaviour that uses the state onto the
  object that owns the state.
- **Composition over inheritance.** Prefer has-a to is-a unless there's true
  substitutability (see LSP). *Symptom:* deep hierarchies; inheriting just to
  reuse one method; a subclass that overrides to *disable* something. *Fix:*
  extract the shared behaviour into a collaborator and compose it.
- **Tell, Don't Ask.** Tell an object to do something; don't pull its data out
  and decide for it. *Symptom:* `if (order.status == PAID) { total +=
  order.amount; }` — the caller interrogates state, then acts. *Fix:* put the
  behaviour on the object that owns the data (`order.charge()`,
  `order.applyDiscount()`).
- **Law of Demeter.** A method should talk to its immediate friends, not
  friends-of-friends. *Symptom:* `a.getB().getC().doThing()` — long navigation
  chains that freeze the whole path in place. *Fix:* hide the walk behind one
  method on the first object (`a.doThing()`).

### Design patterns — problem-first map

This maps a *symptom you've found* to a *pattern that may be the remedy*. Treat
it as a suggestion to evaluate, never a mandate.

| Symptom | Likely pattern |
|---|---|
| Type-conditional logic scattered across the code (`switch`/`if` on a type or enum) | **Strategy** (choose behaviour), **State** (behaviour varies with internal state), **Visitor** (add operations without touching the type), or plain polymorphism |
| Object creation scattered or varying | **Factory Method** (subclass decides), **Abstract Factory** (families of related objects), **Builder** (complex object, many optional parts), **Prototype** (clone) |
| One change must reach many observers, or state must stay in sync | **Observer** (pub/sub), **Mediator** (decouple many-to-many) |
| Add behaviour to objects without a subclass per combination | **Decorator** (wrap), **Composite** (treat one and many uniformly) |
| Two things that must work together but have incompatible interfaces | **Adapter** (translate), **Facade** (simplify a subsystem), **Proxy** (control access) |
| A fixed algorithm skeleton with varying steps | **Template Method** (inheritance) or **Strategy** (composition — usually preferred) |
| Defer, parameterize, or undo an action | **Command**; capture/restore state → **Memento** |
| One instance coordinating a shared resource | **Singleton** — but flag it: global mutable state is a liability; prefer dependency injection |

Two cautions that override the table:

- A pattern only earns its place if it removes *real, present* cost. One `if`
  does not justify a Strategy; one `new` does not justify a Factory.
- Honour the language's idioms. In Python/JS/Go a "Strategy" is often just a
  first-class function, a "Factory" often just a function. Don't transliterate a
  Java class diagram into a language where it doesn't belong.

For the full definition of a pattern — its intent, the genuine trigger, and the
over-engineering warning — read `references/patterns.md` before recommending one
you're not certain about. It covers all 23 GoF patterns, grouped by category.

### Design-level best practices

- **Value objects / immutability** where identity doesn't matter (money, ranges,
  dates).
- **No anemic domain model** — classes that are bare getter/setter bags with the
  logic living elsewhere; move the logic onto the data.
- **Null Object** over scattered null checks, when the "nothing here" case is a
  real abstraction.
- **Small, focused interfaces** — already covered by SRP/ISP; don't
  double-report.

## Report format

Use this exact structure, in chat unless the user asks for a file:

```
# Design review — <unit>

## Verdict
One or two sentences: overall shape, then the single highest-value change. If the
unit is well-designed and you have no findings worth acting on, say so plainly and
stop — a review that says "nothing to change" beats one that manufactures problems
to fill the template.

## Findings (N)
Ordered by severity, then impact. For each finding:

### [Severity] <PRINCIPLE> — <short name>
- **Where** — file/class/method + a short quote of the offending code
- **Problem** — the principle it violates *and* the concrete future pain (not theory)
- **Fix** — the specific refactor; name the pattern if one is the natural remedy
- **Sketch** — a minimal before/after, in the code's own language

## Keep as-is
Things already well-designed, so the user doesn't "fix" them. Omit this section if
there's nothing worth naming.

## Not reviewed
Anything out of scope, with the right skill named — one line. Omit if empty.
```

Tag each finding with the principle using this vocabulary: `SRP`, `OCP`, `LSP`,
`ISP`, `DIP`, `Encapsulation`, `Composition-over-inheritance`, `Tell-Don't-Ask`,
`Law-of-Demeter`, or the pattern name when the remedy is a pattern.

### Severity

- **High** — costs real money or risk now: rigid code blocking a known upcoming
  change, a bug-in-waiting, untestable behaviour. Fix before the next change
  lands.
- **Medium** — will hurt soon: friction that's already present, or the next
  change will collide with it. Fix when touching this code.
- **Low** — worth doing, not urgent; do it opportunistically.
- **Nit** — taste. Say so and move on.

Don't inflate severity — if everything is High, the report is noise. Most
reviews should have at most a couple of High findings, often none.

## What not to do

- **Don't pattern-hammer.** Patterns are remedies for problems you found. "No
  pattern needed" is a valid finding.
- **Don't propose speculative abstraction.** One concrete case that varies does
  not justify a seam; two does. If there's no second case, the plain code is
  fine.
- **Don't edit the code.** This is a report. If the user later asks you to apply
  a specific finding, apply only the ones they picked.
- **Don't re-review line-level style.** Names, comments, and formatting are
  `readable-code`'s job. Stay at the design level: responsibilities,
  dependencies, substitutability, patterns.

## Boundaries

- **Not readability.** Naming, comments, line structure → `readable-code`.
- **Not diff/standards/spec review.** Reviewing a *change* against repo
  standards or a spec → `code-review`.
- **Not architecture.** Module seams, depth, subsystem shape → `codebase-design`
  / `improve-codebase-architecture`.
- **Not minimalism.** Smallest-thing-that-works → `ponytail`.

This skill sits between them: it judges the *design of a unit* — its
responsibilities, dependencies, substitutability, and whether a pattern would
reduce the cost of change.
