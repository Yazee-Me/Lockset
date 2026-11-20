# ASD-STE100 writing rules (Issue 9, January 2025)

This file condenses Part 1 of ASD-STE100. It gives the rule number, the rule,
and the reason to obey it. Read it before you write a long procedure, a manual
section, or a document. For a short chat reply, `SKILL.md` is sufficient.

Part 2 of the standard is the dictionary. The checker in `scripts/` holds the
word data. `word-list.md` gives the common substitutions.

---

## Section 1 — Words

| Rule | Statement |
|---|---|
| 1.1 | Use only words that are approved in the dictionary, technical nouns, or technical verbs. |
| 1.2 | Use an approved word only as its approved part of speech. `test` is approved as a noun. |
| 1.3 | Use an approved word only with its approved meaning. Do not use a different sense of the word. |
| 1.4 | Use only the approved forms of verbs and adjectives. |
| 1.5 | A technical noun is a noun that is correct for your subject. Use the 22 official categories (below). |
| 1.6 | A word that is not in the dictionary can be a technical noun. |
| 1.7 | Do not use a technical noun as a verb. Write `put a cover on the port`, not `cover the port`. |
| 1.8 | Use the technical noun that your industry and your company approve. |
| 1.9 | Use a short technical noun that the reader can understand. |
| 1.10 | Do not use regional words, slang, or jargon. |
| 1.11 | Do not use two different technical nouns for the same item. |
| 1.12 | A technical verb is a verb that is correct for your subject. Use the 4 official categories. |
| 1.13 | Do not use a technical verb as a noun. |
| 1.14 | Use American English spelling. Do not change the spelling of quoted text. |

### Technical noun categories (rule 1.5)

1. Official parts information.
2. Vehicles, machines, and their locations.
3. Tools, support equipment, and their parts.
4. Materials, consumables, and unwanted material.
5. Facilities, infrastructure, and logistic procedures.
6. Systems, components, circuits, and their functions.
7. Mathematical, scientific, and engineering terms.
8. Navigation and geographic terms.
9. Numbers, units of measure, and time.
10. Quoted text.
11. Professional roles, groups, and organizations.
12. Parts of the body.
13. Personal effects, food, and beverages.
14. Medical terms.
15. Official documents and standards.
16. Environmental and operational conditions.
17. Colors.
18. Damage terms.
19. Computer science, information, and communication technology.
20. Civil and military operations.
21. Law and regulations.
22. Animals, plants, and other life forms.

### Technical verb categories (rule 1.12)

1. Manufacturing processes.
2. Computer processes and applications.
3. Instructions for subject fields.
4. Law and regulations.

---

## Section 2 — Multi-word nouns

| Rule | Statement |
|---|---|
| 2.1 | Write multi-word nouns with a maximum of three words. |
| 2.2 | Do not use a multi-word noun as a verb. |

If a term is longer than three words, hyphenate the words that act as one unit
(`read-only file system`), or write it in full the first time and give a short
form that you use after that. A preposition helps: `calibration of the sensor`,
not `sensor calibration procedure value`.

---

## Section 3 — Verbs

| Rule | Statement |
|---|---|
| 3.1 | Use only the verb forms that are in the dictionary. |
| 3.2 | Use only these forms: infinitive, imperative, simple present, simple past, simple future, past participle as an adjective. |
| 3.3 | Use the past participle as an adjective to show a condition (`the disassembled unit`). This is not passive voice. |
| 3.4 | Do not use auxiliary verbs to make complex verb constructions. |
| 3.5 | Do not use an "-ing" form as a verb. |
| 3.6 | Use the active voice. In descriptive writing, use the passive voice only when the agent is unknown. |
| 3.7 | Use a verb to describe an action, not a noun. Write `the meter shows 450 ohms`, not `the meter gives an indication of 450 ohms`. |

Not approved: the perfect tenses (`has adjusted`, `had adjusted`), the
progressive tenses (`is adjusting`, `was adjusting`), and long passives.

| Not STE | STE |
|---|---|
| The operator has adjusted the linkage. | The operator adjusted the linkage. |
| The seat is to be installed before the cushion. | Before you install the cushion, install the seat. |
| The volume control can be adjusted. | You can adjust the volume control. |
| The temperature must be adjusted. | Adjust the temperature. |
| The sleeve will be adjusted by the robot. | The robot will adjust the sleeve. |

Approved modal verbs: `CAN`, `CANNOT`, `WILL`, `MUST`. The word `MUST` shows
an obligation. Do not use `COULD` to show possibility.

---

## Section 4 — Sentences (all writing)

| Rule | Statement |
|---|---|
| 4.1 | Write short, clear sentences that give exact instructions and information. |
| 4.2 | Do not omit words. No contractions. Do not drop articles, subjects, or verbs. |
| 4.3 | Use a vertical list for complex text. |
| 4.4 | Use connecting words and phrases (`and`, `but`, `then`, `thus`) to link related sentences. |
| 4.5 | When necessary, put an article (`the`, `a`, `an`) or a demonstrative adjective (`this`, `these`) before a noun or a multi-word noun. |

### Vertical lists (rule 4.3)

- Put a colon before the list.
- Use the same marker for each item (`-`, a letter, or a number).
- Start each item with a capital letter.
- A colon before a list acts as a period. The part before the colon has a
  maximum of 20 words (procedures) or 25 words (descriptions).
- Each item after the colon is a new sentence. Use the same limit for each item.

---

## Section 5 — Procedural writing (instructions)

| Rule | Statement |
|---|---|
| 5.1 | Write short sentences. Use a maximum of 20 words in each sentence. |
| 5.2 | Write only one instruction in each sentence, unless two or more actions occur at the same time. |
| 5.3 | Write instructions in the imperative (command) form. |
| 5.4 | Give a condition before the command, and use a comma. |
| 5.5 | A note gives information only. Do not put an instruction in a note. |

- The maximum length of a sentence in a note is 25 words.
- Do not use `must` before the imperative form, unless the instruction is
  important for safety or gives an important condition.
- Example condition: `If the pump is running, stop it.`

---

## Section 6 — Descriptive writing (explanations)

| Rule | Statement |
|---|---|
| 6.1 | Give information in small steps, from the general to the specific. |
| 6.2 | Use the same key words and phrases through the text. |
| 6.3 | Write short sentences. Use a maximum of 25 words in each sentence. |
| 6.4 | Use paragraphs. |
| 6.5 | Give each paragraph one topic. |
| 6.6 | Do not put more than six sentences in a paragraph. |

Do not use the imperative form in descriptive writing. Descriptive writing
gives information. If you write a command, you write a procedure.

---

## Section 7 — Safety instructions

| Rule | Statement |
|---|---|
| 7.1 | Use `WARNING` for a risk of injury or death. Use `CAUTION` for a risk of damage to equipment or data. If both apply, use `WARNING`. |
| 7.2 | Start a safety instruction with the command or the condition. |
| 7.3 | Tell the reader the result if they do not obey the instruction. |

A safety instruction is not a note. Do not put a safety instruction in a note.

Example:

```
WARNING: Do not start the engine while the cowling is open.
The propeller can cause injury.
CAUTION: Do not stop the service during the backup.
The archive can become corrupt.
```

---

## Section 8 — Punctuation and word count

| Rule | Statement |
|---|---|
| 8.1 | Use standard punctuation. Do not use the semicolon. |
| 8.2 | Use a hyphen to connect words that are directly related. |
| 8.3 | Use parentheses for an explanation, a reference, an identifier, a step number, an abbreviation, or an alternative term. |
| 8.4 | Count the words in a sentence. |
| 8.5 | Text in parentheses counts as one word of the sentence. |
| 8.6 | Count each of these as one word: a number, a number with its unit, an abbreviation, an alphanumeric identifier, quoted text, a title or heading, a proper noun. |
| 8.7 | A hyphenated word counts as one word. |

A sentence after a colon in a vertical list is a new sentence. Use the same
word limit for each item.

---

## Section 9 — Writing practices

| Rule | Statement |
|---|---|
| 9.1 | When a word-for-word change does not work, write the sentence again with a different construction. |
| 9.2 | Use a word only in the sense that is correct in the context. Do not choose an approved word if it changes the meaning. |
| 9.3 | Do not use a phrasal verb. Write `extinguish the fire`, not `put out the fire`. |
| 9.4 | Be consistent. Use the same term and the same phrasing every time. |

---

## General recommendations (not rules)

- **GR-1**: Keep the conjunction `that` after verbs such as `make sure`, `show`,
  and `recommend`.
- **GR-2**: The preposition `with` has more than one meaning. Write the sentence
  again when a reader can understand it in two ways.
- **GR-3 / GR-4**: Use a pronoun (`it`, `this`, `these`) only when the reader
  knows the noun. If two nouns are possible, write the noun again.
- **GR-5**: Look for false friends. A word can look correct and have the wrong
  meaning in the context.
- **GR-6**: Do not use Latin abbreviations (`e.g.`, `i.e.`, `etc.`). Write `for
  example`, `that is`, or write the items.
- **GR-7**: Use inclusive language.
- **GR-8**: A possessive form (`the manufacturer's instructions`) is permitted.
  If you are not sure, write `the instructions from the manufacturer`.

---

Source: ASD-STE100 Simplified Technical English, Issue 9 (January 2025), Part 1
(Writing rules), Aerospace, Security and Defence Industries Association of
Europe. This file is a condensed working summary, not a reproduction of the
standard. Download the standard at https://www.asd-ste100.org.
