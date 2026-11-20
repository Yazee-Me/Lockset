---
name: domain-glossary
description: Keep one vocabulary for a domain across code, documents, and the product UI. Use when naming a domain concept, translating a term for the UI, adding a glossary entry, or reconciling terms that drifted between code and copy.
---

# Domain glossary

## The glossary is canonical

- The repository's `CONTEXT.md` holds the glossary: the English term, the
  canonical term in the product's language, a one-sentence definition, and an
  `_Avoid_` list of the names that must not come back.
- When a term is missing, add it before using it. A name invented in code and
  fixed later costs a migration; a name written down first costs a sentence.

## Three audiences, three rules

- **System artefacts** — code, identifiers, schema, enum values, payloads,
  infrastructure, commits, tests, file names — use the English term only. The
  product's language never reaches the schema.
- **Documents** — English prose, with the canonical term in the product's
  language in parentheses the first time a domain term appears. Keep that term
  verbatim; it is the legal or professional name, not a translation hint.
- **Product UI** — the product's language only, in every user-facing string:
  labels, buttons, empty states, validation messages, exports, emails. No
  English leaks into the product surface.

## Keep them apart

- The English term names the thing in code; the product term names it to the
  user. Both are correct in their layer and neither substitutes for the other.
- A renaming that crosses layers is a decision on a ticket, not a side effect of
  a refactor.
