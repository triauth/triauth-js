# AI security reviews

This directory holds structured security reviews of the triauth protocol and each public
`Triauth.*` API method, produced by frontier AI models (via the Claude Code and Codex CLIs).

> [!IMPORTANT]
> These are an advisory signal, not a security audit.

See the [trust model](https://www.triauth.org/protocol/trust-model) and the README's
[Best Practices and Security Considerations](../../README.md#best-practices-and-security-considerations) for the security model, and
[`../../SECURITY.md`](../../SECURITY.md) for vulnerability reporting.

## How it works

- One Markdown file per **agent × scope**, at `test/ai-reviews/<agent>/<scope>.md`. The `claude/` directory
  holds the Claude Code CLI reviews and `codex/` the Codex CLI reviews.
- A re-run with a newer model updates the same file in place. The frontmatter records which model produced
  the current version (`model`, `model_id`), the reviewed commit, the date, and the settings.
- Reviews are generated locally with `npm run ai-review` (needs the Claude Code and/or Codex CLIs
  installed and authenticated). See [`GUIDE.md`](_harness/GUIDE.md) for the full procedure and file format,
  and [`TEMPLATE.md`](_harness/TEMPLATE.md) for the skeleton.

## Status legend

Each review file declares a top-level `status` in its YAML frontmatter:

Status is a rollup of the worst **open** (non-`[reviewed]`) finding. The runner computes it when it stamps a review:

| Status | Meaning |
|--------|---------|
| `good-to-go` | No open finding of `medium` or higher (`low`/`info` don't count, and `[reviewed]` findings are excluded). |
| `warnings` | Worst open finding is `medium`. |
| `fatal` | At least one open `high`/`critical` finding. |

## Finding conventions

Findings live under `## Findings` as `###` headings:

```
### [AUTH-001] [medium] Short title
```

- **Stable IDs** (`<PREFIX>-<NNN>`) are append-only per file, so re-runs *update* existing findings by
  ID instead of duplicating them. IDs are never renumbered or reused.
- **`[reviewed]`** in the heading marks a finding a **human** has vetted. Human adds the tag by hand, together
  with a `> ` note in the body, and set `status` from the table above. AI runs must preserve `[reviewed]` findings and 
  their human notes verbatim.
