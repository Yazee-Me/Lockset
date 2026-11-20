# Jira ticket templates

Description templates for Yazee Jira projects. The project's own instructions
name the Jira site, project key, area tags, and branch/PR naming. These files
hold the shared format only. Copy the file matching the issue type into the
Description field.

Jira Cloud has no native per-issue-type default description, so these files are
the canonical format rather than a Jira-side setting. Nothing here is wired into
Jira; the templates are applied by hand or by an agent.

## Titles

Every ticket is titled `[<AREA>] <description>`. The project's instructions
define which tags apply; the default vocabulary across the Yazee projects is
`[API]`, `[UI]`, `[MOBILE]`, `[LANDING]`, `[INFRA]`, `[DOCS]`, `[DESIGN]`,
`[SDK]`, and `[TOOLING]`.

The title is not only for Jira: git copies it. The branch, commit subject, and
PR title derive from the project key and this title. Write the description as
the sentence a reader of the git log should get, and keep the whole title
inside 72 characters with the key and `type(scope): ` in front of it.

## Which type, when

| Type                    | Use it for                                                                       |
| ----------------------- | -------------------------------------------------------------------------------- |
| [Story](./story.md)     | A functional change — what a user or the business can do changes                  |
| [Task](./task.md)       | A non-functional change — a package update, a refactor, engineering, ops, or docs |
| [Bug](./bug.md)         | A defect — something behaves wrong today                                          |
| [Subtask](./subtask.md) | One step of a Task or a Story                                                     |
| [Epic](./epic.md)       | One whole feature — a container for its Stories, Tasks, and Bugs                  |

When a change is both, decide by what it delivers: a capability the business
can use is a Story, and the work that only supports it is a Task.

## Conventions the templates assume

- The section vocabulary is shared across types (`Work`, `Done when`, `Notes`,
  `Out of scope`, `Evidence`) so tickets read alike and can be parsed the same
  way.
- Titles are `[<AREA>] <description>` and become the branch, the commit subject,
  and the PR title in git.
- Every Story, Task, and Bug belongs to an Epic. A Subtask inherits its parent's
  Epic.
- Project-specific evidence belongs in the project's instructions: Sentry keys,
  log datasets, release format, or deployment environment.
