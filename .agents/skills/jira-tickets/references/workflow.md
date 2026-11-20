# Filing and moving a ticket

## Create it

```bash
acli jira workitem create --summary "[<AREA>] <description>" \
  --project <KEY> --type <Type> --description-file <path>
```

- Write the description body from the matching reference file to a temporary
  file first; `--description-file` keeps the formatting.
- Set the parent epic in the same call with `--parent`. Create the epic first
  when none covers the work.
- `acli jira workitem create` prints the new key. Use that key for the branch,
  the commit, and the PR.
- `acli jira workitem view <KEY> --json` reads a ticket back; add
  `--fields summary,status,parent` to keep the output small.

## Move it

```bash
acli jira workitem transition --key <KEY> --status "<status>"
```

- Read the statuses the board actually has. Column names differ per project and
  a transition that does not exist fails; never invent one.
- `In Progress` the moment the branch is cut. The review state when the PR
  opens, unless CI moves it there. `Done` only after the merge.
- Where CI moves the ticket, do not move it by hand. The project's instructions
  name the workflow that does.

## Keep the board honest

- A branch that exists while the ticket still reads `To Do` is wrong.
- A ticket with an open PR still in `In Progress` is wrong.
- A merged change whose ticket still sits in review is equally wrong; close it
  with a comment naming the PR and the release.
