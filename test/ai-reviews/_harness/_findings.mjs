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
