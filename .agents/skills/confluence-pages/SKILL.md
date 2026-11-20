---
name: confluence-pages
description: Author, place, link, and verify Confluence pages for Yazee products. Use when writing an exploration, a design, a proposal, a decision write-up, or a meeting note, or when a ticket needs its artefact page.
---

# Confluence pages

An artefact is anything written to be read rather than deployed. Artefacts live
in the product's Confluence space, not in the repository; the repository keeps
only the ADRs, the runbook, and the architecture document.

The project's instructions name the space key and its homepage. The site holds
other products' spaces, so address the space by key and never by search.

## Place the page

- Create it at the space homepage, or nest it under the page a reader would look
  in. Do not leave it floating at the space root when a parent exists.
- One page per artefact, titled as the thing it describes.

## Write the page

A write goes through the `atlassian` MCP server: `createConfluencePage` for a new
page, `updateConfluencePage` for an edit. `acli` cannot write a page; it reads
them.

- Load `getContentFormatGuide` for the tool before the first write, and build
  the body in the format the guide names.
- Registered decisions are dated and owned: what was decided, why, and what was
  rejected. A decision that ships with the code is an ADR in the repository
  instead.
- Author ASCII diagrams flush-left: Confluence trims leading whitespace on the
  first line of a code block.
- Match the space's existing house style when it has one; the project's
  instructions say whether it does.

## Link both ways

- An artefact that has a ticket names the key on the page.
- The ticket carries the page URL.
- Both links, every time. A page no ticket names is a page nobody finds.

## Verify

- Read every page back after the write, as rendered HTML and not as markdown:
  `acli confluence page view --id <ID> --body-format view`. Dates, panels, and
  decision lists are nodes that render in Confluence but vanish from a markdown
  export.
- `--json` returns the same body with its metadata; `--body-format storage`
  returns the stored XHTML when you need the source.
- Reading needs the page `--id`, not its title. The URL carries the id.
