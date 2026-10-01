---
model: <display name, e.g. Fable 5.1>
model_id: <api id, e.g. claude-fable-5-1>
scope: <protocol | authenticate | check | ping | whois | attest | sign | stamp | verify | validate>
lib_version: <e.g. 1.0.0-beta.1>
commit: <short sha, e.g. 41d28e8>
reviewed_at: <YYYY-MM-DD>
status: <good-to-go | warnings | fatal>
summary: <one-line verdict>
settings:
  effort: <e.g. high>
---

# <Model> review — Triauth.<scope>

## Summary

<A few sentences: overall posture and headline concerns, or "no issues found".>

## Findings

<!-- One ### per finding. Heading grammar: ### [<PREFIX>-NNN] [severity] [reviewed]? Title
     severity ∈ info|low|medium|high|critical. Do NOT add [reviewed] yourself.
     If there are no findings, replace this block with the single line: _No findings._ -->

### [PREFIX-001] [medium] Short, specific title
**Location:** `src/...`
**Description:** What the issue is and why it matters.
**Recommendation:** What to change or verify.
