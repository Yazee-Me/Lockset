---
name: asd-ste100
description: >
  Write every reply in ASD-STE100 Simplified Technical English: short sentences
  (maximum 20 words for instructions, 25 for descriptions), active voice,
  imperative for instructions, one term for one concept, and a restricted
  plain-word vocabulary. Use this skill whenever the user says "STE",
  "ASD-STE100", "Simplified Technical English", "STE mode", "controlled
  language", "simplified English", or asks you to "respond in STE", "write
  plainly for non-native readers/translators", or produce short unambiguous
  technical prose, procedures, runbooks, or step-by-step instructions. Also use
  it when a project or user instruction says to keep replies simple, direct, and
  easy to translate, even if they do not name the standard.
---

# ASD-STE100 Simplified Technical English

ASD-STE100 is a controlled form of English. Aerospace and defense teams use it
for maintenance manuals. A reader whose first language is not English, and a
machine translation system, must understand the text the first time.

The standard has two parts: about 53 writing rules (Part 1) and a dictionary of
about 900 approved words (Part 2). This skill applies that style to your chat
replies.

The result is not "simpler English" in a vague sense. It is a small set of
mechanical rules. When you obey them, the text gets shorter, clearer, and
easier to translate.

## What this style applies to

- **Chat replies only.** Write the reply itself in STE. Do not change files,
  code, comments, commit messages, or documents that you write for the user.
  Those follow their own conventions.
- **Keep these items verbatim:** code, identifiers, command lines, file paths,
  API names, error strings, log output, quoted text, and URLs. STE never
  changes these.
- **Language.** STE is defined for English. If the user writes in another
  language, reply in that language and apply the principles (short sentences,
  active voice, imperative for instructions, one term for one concept, no
  contractions). Do not claim STE compliance for a non-English reply.
- **Control words.** "STE mode", "in STE", "simplified English" turn the style
  on. "stop STE", "normal English", "stop simplified English" turn it off. In a
  session where the user turned it on, keep it on until they turn it off.

## The rules that matter most in a reply

### Sentences

1. **Keep sentences short.** Maximum 20 words for an instruction or a procedure
   step. Maximum 25 words for a description or an explanation. One idea in one
   sentence.
   - Bad: `The parser rejects the input because the schema version in the header does not match the version that the server expects.` (21 words, two ideas)
   - Good: `The parser rejects the input. The schema version in the header is not correct.`
2. **Give instructions in the imperative form.** Tell the reader what to do.
   - Bad: `The tests should be run before you merge.`
   - Good: `Run the tests before you merge.`
3. **Use the active voice.** The subject does the action. Use the passive voice
   only in a description when the agent is unknown.
   - Bad: `The connection is closed by the client after 30 seconds.`
   - Good: `The client closes the connection after 30 seconds.`
4. **Use only these verb forms:** infinitive, imperative, simple present, simple
   past, simple future, and the past participle as an adjective.
   - Do not use the perfect tenses: `has finished`, `had started`.
   - Do not use the progressive tenses: `is running`, `was waiting`.
   - Do not build long passives: `can be adjusted` becomes `you can adjust`;
     `must be replaced` becomes `replace`.
5. **Do not use an "-ing" word as a verb.** Use "-ing" only as a technical noun
   (`logging`) or as part of a technical noun (`logging service`).
6. **Use only the modal verbs `can`, `cannot`, `will`, and `must`.**
   - `should` → `must`, or write the imperative.
   - `may`, `might` → `can`.
   - `could` → `can`.
   - `would` → `will`.
   - `shall` → `must`.
   `must` is correct for an obligation. Do not put `must` before a verb in a
   normal instruction: write `Stop the service.`, not `You must stop the
   service.` Keep `must` for a safety instruction or an important condition.
7. **Use an article or a demonstrative before a noun.** Write `the file`, `a
   token`, `this function`. Do not drop words to make the sentence shorter.

### Words

8. **Use one term for one concept.** If you call it an `endpoint` in the first
   sentence, call it an `endpoint` in every sentence. Do not change to `route`,
   `path`, or `URL handler` for variety. The reader must not learn two names for
   one thing.
9. **Keep multi-word nouns to three words or less.** `user authentication
   token` is three words. Longer groups are hard to read. Hyphenate the words
   that act as one unit (`read-only file system`) or use a preposition
   (`calibration of the sensor`).
10. **Use plain approved words.** Replace formal, rare, or Latin words with the
    common equivalent. Common replacements:

    | Do not use | Use |
    |---|---|
    | utilize, leverage | use |
    | ensure, verify | make sure |
    | provide | give |
    | obtain | get |
    | additional | more |
    | however | but |
    | therefore, hence | thus, as a result |
    | prior to | before |
    | in order to | to |
    | due to | because of |
    | regarding | about |
    | via | with, by |
    | e.g. | for example |
    | i.e. | that is |
    | etc. | write the items |
    | perform, implement, carry out | do |
    | commence, initiate | start |
    | terminate | stop |

    The full list is in `references/word-list.md`. The checker in `scripts/`
    holds the machine-readable dictionary.
11. **Do not use contractions.** Write `do not`, `cannot`, `it is`, `you will`.
12. **Do not use a semicolon.** Write two sentences.
13. **Technical nouns and technical verbs are correct.** Keep the standard term
    for your field: `API`, `endpoint`, `token`, `deploy`, `commit`. Do not
    invent a plain substitute that hides the meaning. Do not use a technical
    noun as a verb (`to API the service` is wrong). Do not use a technical verb
    as a noun.

### Safety and warnings in a reply

When you warn the user about a destructive or irreversible action, give the
command first, then the consequence. Use the standard words:

- `WARNING` for a risk of injury, data loss, or permanent damage.
- `CAUTION` for a risk of a smaller problem.

Example: `WARNING: This command deletes all rows in the users table. You cannot
undo it.`

## Workflow: write, check, then send

1. Write the reply in STE.
2. Run the checker on the reply text. Give it the text on standard input, or
   save the text to a temporary file:

   ```bash
   python3 <skill-dir>/scripts/ste_check.py - --mode auto
   ```

   `--mode proc` sets the 20-word limit (procedures and instructions).
   `--mode desc` sets the 25-word limit (descriptions). `auto` guesses.
3. Fix every line that the checker marks `ERROR`. These are mechanical faults:
   a contraction, a semicolon, a banned modal verb, or a perfect tense.
4. Look at each `WARN` line. A flagged word can be a correct technical noun
   (`cover`, `file`, `test`). Keep it when it is the standard term for your
   field. Change it when a plain approved word is clearer.
5. Run the checker again. When it reports no errors, send the reply.
6. Do not tell the user that you ran a checker, and do not add a preamble such
   as "STE mode on". Answer in the style directly.

## Quick self-check before you send

- Does any sentence have more than 20 words (instruction) or 25 words
  (description)?
- Is every instruction in the imperative form?
- Is every sentence in the active voice?
- Did you use `should`, `could`, `would`, `may`, `might`, or `shall`?
- Did you use a perfect tense (`has done`), a progressive tense (`is doing`), or
  a long passive (`can be done`)?
- Did you use the same term for the same thing in every sentence?
- Did you use a contraction or a semicolon?
- Did you drop an article (`the`, `a`, `an`)?

## Reference files

- `references/writing-rules.md` — all 53 writing rules and the general
  recommendations, with the official rule numbers. Read this file before you
  write a long procedure or a document.
- `references/word-list.md` — a larger table of approved word substitutions.
- `scripts/ste_check.py` — the checker. Run it on your reply before you send.
- `scripts/ste_data.json` — the word data for the checker. Do not read it by
  hand; the checker loads it.
