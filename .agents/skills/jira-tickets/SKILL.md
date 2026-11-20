---
name: jira-tickets
description: Create, title, and format Jira tickets for Yazee projects. Use when filing a ticket, editing a description, choosing an issue type, or checking whether work is tracked.
---

# Jira tickets

The project's own instructions name the Jira project key, site, and area tags.
This skill supplies the shared format. Read the reference for the issue type
before writing the ticket.

## Files

- `references/README.md` — title rules, issue-type choice, and shared conventions.
- `references/workflow.md` — creating a ticket with `acli`, moving it across the
  board, and keeping the board honest.
- `references/story.md` — functional change.
- `references/task.md` — non-functional change.
- `references/bug.md` — defect.
- `references/subtask.md` — one step of a Task or Story.
- `references/epic.md` — container for a whole feature.

## Rules

1. File the ticket before the first edit. A change that lands as one PR gets one
   ticket first.
2. Title it `[<AREA>] <description>`. The project's instructions define the area
   tags and the key.
3. One ticket per unit of work. Do not stretch an existing ticket to cover an
   unrelated change.
4. The ticket title is the source of truth for the branch, commit subject, and
   PR title.
5. Copy the matching reference file into the Jira Description field. Jira Cloud
   has no native per-issue-type default description. Create the ticket with
   `acli jira workitem create --description-file`; see
   `references/workflow.md`.
6. When a change is both functional and supporting, decide by what it delivers:
   a capability the business can use is a Story; the work that only supports it
   is a Task.
7. Every Story, Task, and Bug belongs to an Epic. Create the Epic first when none
   covers the work. A Subtask inherits its parent's Epic.
8. Keep the title inside 72 characters with the key and `type(scope): ` in front
   of it. The title is the commit subject, so a title that does not fit forces a
   commit subject that does not match it.
9. Move the ticket as the work moves, and never guess a transition name. The
   project's instructions name the board columns and any CI that moves it.
