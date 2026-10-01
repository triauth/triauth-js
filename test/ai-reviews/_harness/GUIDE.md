# Review guide (read this before producing a review)

This is the harness specification for an AI security review of triauth-js. A review evaluates **one
scope** (the protocol as a whole, or one public API method) and is written to a single Markdown file.
You are normally invoked by `test/ai-reviews/_harness/run.mjs` (`npm run ai-review`), which passes you a scope and
then stamps the controlled metadata after you write — but the format below is authoritative either way.

## Procedure

1. **Pick a scope** (one from the table below). You are usually told which one.
2. **Read the code for that scope** — the "Primary source" files and "Also consider" files.
   Then read the [Best Practices and Security Considerations](../../../README.md#best-practices-and-security-considerations)
   section and the matching method section of [`../../../README.md`](../../../README.md), and the
   [trust model](https://www.triauth.org/protocol/trust-model), so your review is grounded in the intended security model.
3. **Follow the execution trace of any relevant methods** - so that you gain deep understanding of how it works.
4. **Read the existing review file** `test/ai-reviews/<agent>/<scope>.md` if it exists. You MUST
   follow the finding-ID reuse rule below so the file updates instead of accumulating duplicates.
5. **Write/update** `test/ai-reviews/<agent>/<scope>.md` using the format in the next section.
   Start from [`TEMPLATE.md`](TEMPLATE.md) if the file is new.
6. Do not peek into other scope and/or other agents' review files as they may interfere with your jugement.

## File format

YAML frontmatter, then a `## Summary` and a `## Findings` section:

```yaml
---
model: Fable 5.1
model_id: claude-fable-5-1
scope: authenticate
lib_version: 1.0.0-beta.1
commit: 41d28e8
reviewed_at: 2026-06-15
status: warnings              # computed by the runner; warnings here = one open medium finding (AUTH-001)
summary: One-line verdict.    #   (the info finding AUTH-002 is [reviewed], so it is excluded)
settings:
  effort: high
---
```

> **You only own `scope`, `status`, `summary`, and the `## Findings` body.**
> The runner overwrites `model`, `model_id`, `lib_version`, `commit`, `reviewed_at`, and `settings`
> with the exact values it ran you under. Fill them with best-effort placeholders; don't depend on them.

Body:

```markdown
# <Model> review — Triauth.<scope>

## Summary
A few sentences: overall posture and the headline concerns (or "no issues found").
Also state if the library is safe to use in mission-critical production systems (but do not take into account its beta status). 
If not, always add a CRITICAL finding with the reason behind it. 

## Findings

### [AUTH-001] [medium] Short, specific title
**Location:** `src/api/authentication.js` (add `:line` if useful)
**Description:** What the issue is and why it matters, in protocol/security terms.
**Recommendation:** What to change or verify.

### [AUTH-002] [info] [reviewed] Another finding
**Location:** `src/challenge_response_flow.js`
**Description:** ...
> **Human review (zz, 2026-06-15):** Acknowledged — by design, documented in the README. Accepted.
```

If you find nothing, set `status: good-to-go`, write a one-line `## Summary`, and leave `## Findings`
with a single line: `_No findings._`

## Finding heading grammar

`### [<ID>] [<severity>] [reviewed]? <title>`

- **`<ID>`** = `<PREFIX>-<NNN>`, zero-padded (e.g. `AUTH-003`). Prefixes per scope:
  `protocol`→`PROTO`, `authenticate`→`AUTH`, `check`→`CHECK`, `ping`→`PING`, `whois`→`WHOIS`,
  `attest`→`ATTEST`, `sign`→`SIGN`, `stamp`→`STAMP`, `verify`→`VERIFY`, `validate`→`VALID`.
- **`<severity>`** = one of `info`, `low`, `medium`, `high`, `critical`.
- **`[reviewed]`** = human sign-off marker — **never add or remove this yourself**, and never alter a
  finding that has it or its `> **Human review …**` note.

### ID reuse rule (idempotency)
- Before writing, read the existing file and collect its finding IDs.
- For an issue that already has an ID, **reuse that ID** and update its body/severity in place.
- Allocate the next sequential number **only** for a genuinely new issue.
- Never renumber, delete, or recycle an ID. This is what keeps re-runs duplicate-free.

### Status rule
The file `status` is a rollup of the worst **open** (non-`[reviewed]`) finding. `run.mjs` computes it
for you from the per-finding severities — you don't hand-set it. (If writing a review by hand, apply
the same table.)

| Worst open finding | `status` |
|--------------------|----------|
| `critical` or `high` | `fatal` |
| `medium` | `warnings` |
| `low`, `info`, or none | `good-to-go` |

- A `[reviewed]` finding is human-accepted and **excluded** from the rollup, so a `medium`-or-worse
  finding leaves the rollup once it is **fixed** or **reviewed-and-accepted** (mark `[reviewed]` with a
  note).
- Your job is just to get each finding's **severity** right; the runner derives `status` when it stamps
  the file. A human who later marks a finding `[reviewed]` applies the same table to `status` by hand.

## Scope → source files

| Scope | Primary source | Also consider |
|-------|----------------|---------------|
| `protocol` | `src/signature.js`, `src/multi_signature.js`, `src/challenge.js`, `src/response.js`, `src/challenge_response_flow.js` | `src/resolvers/`, `src/verifiers/`, `src/helpers.js`, `README.md` (Best Practices and Security Considerations) |
| `authenticate` | `src/api/authentication.js` | `src/challenge_response_flow.js`, `src/signature.js` |
| `check` | `src/api/authentication.js` | identity/DNS models in `src/identity*.js` |
| `ping` | `src/api/authentication.js` | `src/signature.js` |
| `whois` | `src/api/identity.js` | `src/identity_keys.js`, `src/identity_domain.js`, `src/authentication_endpoint.js` |
| `attest` | `src/api/attestation.js` | `src/signature.js`, `src/verifiers/` |
| `sign` | `src/api/signing.js` | `src/signature.js` |
| `stamp` | `src/api/signing.js` | `src/signature.js` |
| `verify` | `src/api/signing.js` | `src/multi_signature.js`, `src/verifiers/` |
| `validate` | `src/api/validation.js` | `src/validator.js`, `src/protocol.js` |
