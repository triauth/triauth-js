// Pure helpers for parsing findings and rolling up status.
// Kept separate from run.mjs so they can be unit-tested without launching agents.

// groups: 1=prefix (incl. id+severity brackets), 2=id, 3=severity, 4=[reviewed] marker, 5=rest
export const HEADING = /^(###\s+\[([A-Z]+-\d+)\]\s+\[([a-z]+)\])(\s+\[reviewed\])?(\s.*)?$/;
export const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export function findingIds(text) {
  const ids = new Set();
  for (const line of text.split(/\r?\n/)) { const m = HEADING.exec(line); if (m) ids.add(m[2]); }
  return ids;
}

// The number of a finding ID: `AUTH-003` -> 3.
export function findingNumber(id) {
  return Number(id.slice(id.lastIndexOf('-') + 1));
}

// The highest finding number in the text, 0 when it has no finding. Numbers are append-only: a review's
// `next_id` never drops below this plus one, so a removed finding's number is never used again.
export function highestFindingNumber(text) {
  let highest = 0;
  for (const id of findingIds(text)) highest = Math.max(highest, findingNumber(id));
  return highest;
}

// The [reviewed] findings of the text, keyed by ID, each as the lines a run must carry over verbatim: its
// heading and the quoted human review note(s) under it.
export function reviewedEntries(text) {
  const entries = new Map();
  let current = null;
  for (const line of text.split(/\r?\n/)) {
    const m = HEADING.exec(line);
    if (m) { current = m[4] ? [line] : null; if (current) entries.set(m[2], current); continue; }
    if (/^#{1,2} /.test(line)) { current = null; continue; }
    if (current && line.startsWith('> ')) current.push(line);
  }
  return entries;
}

// What a run must not do to the findings it was given: bring back a number below the committed `next_id`
// (`committedNextId`, with `beforeIds` the committed IDs), or drop or alter a [reviewed] finding it started
// from (`beforeReviewed`, as `reviewedEntries` lists them). Returns the fault as text, or null.
export function findingsFault({ beforeIds, committedNextId, beforeReviewed }, text) {
  const recycled = [...findingIds(text)].filter(id => !beforeIds.has(id) && findingNumber(id) < committedNextId);
  if (recycled.length) return `reused the retired number(s) ${recycled.join(', ')} (next_id is ${committedNextId})`;
  const kept = reviewedEntries(text);
  for (const [id, lines] of beforeReviewed) {
    if (kept.get(id)?.join('\n') !== lines.join('\n')) return `dropped or altered the [reviewed] finding ${id}`;
  }
  return null;
}

// Roll up status from the worst OPEN (non-[reviewed]) finding: high/critical→fatal, medium→warnings,
// low/info/none→good-to-go. [reviewed] findings are accepted and excluded.
export function computeStatus(text) {
  let worst = -1;
  for (const line of text.split(/\r?\n/)) {
    const m = HEADING.exec(line);
    if (!m || m[4]) continue;                       // skip non-headings and [reviewed] findings
    if (m[3] in SEV_RANK) worst = Math.max(worst, SEV_RANK[m[3]]);
  }
  if (worst >= SEV_RANK.high) return 'fatal';
  if (worst === SEV_RANK.medium) return 'warnings';
  return 'good-to-go';
}
