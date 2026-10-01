// Minimal YAML-frontmatter parse/serialize for the ai-reviews format.
//
// Deliberately tiny and dependency-free (the library has zero runtime deps and we keep the tooling
// the same). It handles exactly what our review files use: a leading `---` block of top-level
// `key: value` pairs, plus one nested map (`settings:`) with 2-space-indented children. Anything
// fancier than that is out of scope on purpose.

function stripQuotes(v) {
  if (v.length >= 2 && ((v[0] === '"' && v.at(-1) === '"') || (v[0] === "'" && v.at(-1) === "'"))) {
    return v.slice(1, -1);
  }
  return v;
}

function formatScalar(v) {
  const s = String(v);
  // Quote when a bare scalar could confuse a YAML reader (leading indicator char, or a `: ` / `#`).
  if (s === '' || /^[\s\-?:>@&*!|%#'"[\]{}]/.test(s) || /:\s|\s#|\s$/.test(s)) {
    return `"${s.replace(/"/g, '\\"')}"`;
  }
  return s;
}

// parse(text) -> { data, body }. `data` is a plain object; nested maps become objects.
export function parse(text) {
  const m = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/.exec(text);
  if (!m) return { data: {}, body: text };
  const body = text.slice(m[0].length);
  const data = {};
  let block = null; // current nested-map key, or null at top level
  for (const raw of m[1].split(/\r?\n/)) {
    if (!raw.trim() || raw.trimStart().startsWith('#')) continue;
    const indented = /^\s+\S/.test(raw);
    const line = raw.trim();
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim();
    const val = stripQuotes(line.slice(idx + 1).trim());
    if (indented && block) {
      data[block][key] = val;
    } else if (val === '') {
      data[key] = {};
      block = key;
    } else {
      data[key] = val;
      block = null;
    }
  }
  return { data, body };
}

// serialize(data, body) -> text. Emits keys in insertion order; nested objects become indented maps.
export function serialize(data, body) {
  const lines = ['---'];
  for (const [k, v] of Object.entries(data)) {
    if (v && typeof v === 'object') {
      lines.push(`${k}:`);
      for (const [sk, sv] of Object.entries(v)) lines.push(`  ${sk}: ${formatScalar(sv)}`);
    } else {
      lines.push(`${k}: ${formatScalar(v)}`);
    }
  }
  lines.push('---');
  return `${lines.join('\n')}\n\n${body.replace(/^\r?\n+/, '')}`;
}
