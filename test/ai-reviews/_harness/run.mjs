#!/usr/bin/env node
// AI-review runner (`npm run ai-review`).
//
// Every (agent × scope) pair is one headless CLI run. All runs start at once (cap them with
// --jobs), and each one independently:
//   1. launches the agent CLI so it writes/updates test/ai-reviews/<agent>/<scope>.md following
//      GUIDE.md, with the CLI's output captured to a per-run log file, then
//   2. checks that the run was served by the model the adapter names (where the CLI reports it),
//      then stamps the controlled frontmatter (model/version/commit/date/settings) authoritatively
//      and reports how many finding IDs are new since the last commit.
//
// It never commits; read the reviews, inspect `git diff test/ai-reviews/` and commit yourself.
//
// Usage:
//   npm run ai-review                                  # all agents × all scopes, all at once
//   npm run ai-review -- --agent=claude --scope=verify # narrow it down
//   npm run ai-review -- --effort=medium               # override the reasoning effort
//   npm run ai-review -- --jobs=4                      # at most 4 agent CLIs running at a time
//
// NOTE: requires the relevant CLI(s) installed and authenticated (`claude`, `codex`). The exact
// flags below were written against claude-code 2.1.x and codex-cli 0.158; adjust the adapters if your
// CLI versions differ. Confirm the codex `model`/`model_id` matches what your account actually runs.

import { readFileSync, writeFileSync, appendFileSync, rmSync, mkdirSync, mkdtempSync, existsSync, openSync, closeSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execSync, spawn, spawnSync } from 'node:child_process';
import { parse, serialize } from './_frontmatter.mjs';
import { findingIds, computeStatus } from './_findings.mjs';

const harnessDir = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(harnessDir, '..', '..', '..');
const pkg = JSON.parse(readFileSync(join(repoRoot, 'package.json'), 'utf8'));

const SCOPES = ['protocol', 'authenticate', 'check', 'ping', 'whois', 'attest', 'sign', 'stamp', 'verify', 'validate'];

// Per-agent adapters. `id` names the review directory (test/ai-reviews/<id>/) and the `--agent`
// filter. `params` is an open map (effort + anything else) and `cmd` maps it to that CLI's flags.
// Both the params and the resolved model are recorded in each review's `settings`/`model_id`.
// `env` is added to the CLI's environment. `verify({ stdout, stderr }, model_id)` inspects the
// CLI's output after a clean exit and returns a problem string, or null when the run was served by
// `model_id`; an adapter without it is judged on exit status and the written file alone.
const AGENTS = [
  {
    id: 'claude',
    model: 'Fable 5.1',
    model_id: 'claude-fable-5-1',
    params: { effort: 'max' },
    // Claude Code re-runs a safety-refused request on a fallback model by default (Fable's
    // dual-use classifier routes cyber/bio refusals to Opus) and may swap an unavailable model.
    // CLAUDE_CODE_NO_MODEL_FALLBACK forbids every substitution, so such a run ends instead.
    env: { CLAUDE_CODE_NO_MODEL_FALLBACK: '1' },
    cmd: (prompt, p) => ['claude', [
      '-p', prompt,
      '--model', 'claude-fable-5-1',
      '--effort', p.effort,
      '--permission-mode', 'acceptEdits',
      '--allowedTools', 'Read', 'Edit', 'Write', 'Grep', 'Glob',
      '--output-format', 'json',
    ]],
    // The JSON result carries how the session stopped and `modelUsage`, keyed by the model that
    // actually answered each request (a server-side fallback shows up under the fallback's id).
    verify: ({ stdout }, modelId) => {
      let r;
      try { r = JSON.parse(stdout); } catch { return 'printed no JSON result'; }
      if (r.is_error || r.subtype !== 'success') return `ended with ${r.subtype}${r.errors?.length ? `: ${r.errors.join('; ')}` : ''}`;
      if (r.stop_reason === 'refusal') return 'refused the task (stop_reason: refusal)';
      const served = Object.entries(r.modelUsage ?? {}).map(([id, u]) => u.canonicalModel ?? id);
      if (!served.length) return 'reported no model usage';
      const others = served.filter(id => id !== modelId);
      return others.length ? `served by ${[...new Set(others)].join(', ')}` : null;
    },
  },
  {
    id: 'codex',
    model: 'GPT-6 Astra',
    model_id: 'gpt-6-astra',
    params: { effort: 'xhigh' },
    cmd: (prompt, p) => ['codex', [
      'exec', prompt,
      '-m', 'gpt-6-astra',
      '-s', 'workspace-write',
      '-c', `model_reasoning_effort=${p.effort}`,
      '--skip-git-repo-check',
      '--color', 'never',
    ]],
    // codex exec prints its transcript on stderr: a `model: <id>` header line and, when OpenAI
    // reroutes a turn to another model, `model rerouted: <from> -> <to> (<reason>)`. The --json
    // stream carries neither, so the adapter stays on text output and reads the transcript.
    verify: ({ stdout, stderr }, modelId) => {
      const all = `${stderr}\n${stdout}`;
      const rerouted = /^model rerouted: (\S+) -> (\S+) \((.*)\)$/m.exec(all);
      if (rerouted) return `served by ${rerouted[2]} (model rerouted: ${rerouted[1]} -> ${rerouted[2]}, ${rerouted[3]})`;
      const header = /^model: (\S+)$/m.exec(all);
      if (!header) return 'printed no model header';
      return header[1] === modelId ? null : `configured for ${header[1]}`;
    },
  },
];

// ---- args -----------------------------------------------------------------
const opts = {};
for (const a of process.argv.slice(2)) {
  const m = /^--([^=]+)(?:=(.*))?$/.exec(a);
  if (m) opts[m[1]] = m[2] ?? true;
}
const agents = AGENTS.filter(a => !opts.agent || a.id === opts.agent);
const scopes = SCOPES.filter(s => !opts.scope || s === opts.scope);
const jobs = 'jobs' in opts ? Number(opts.jobs) : Infinity;   // Infinity = every run at once
if (!agents.length) { console.error(`Unknown --agent. Known: ${AGENTS.map(a => a.id).join(', ')}`); process.exit(2); }
if (!scopes.length) { console.error(`Unknown --scope. Known: ${SCOPES.join(', ')}`); process.exit(2); }
if (jobs !== Infinity && !(Number.isInteger(jobs) && jobs >= 1)) { console.error('--jobs takes a positive integer.'); process.exit(2); }

const headCommit = execSync('git rev-parse --short HEAD', { cwd: repoRoot }).toString().trim();
const today = new Date().toISOString().slice(0, 10);

// ---- helpers --------------------------------------------------------------
function committedVersion(relPath) {
  const r = spawnSync('git', ['show', `HEAD:${relPath}`], { cwd: repoRoot, encoding: 'utf8' });
  return r.status === 0 ? r.stdout : '';
}

function buildPrompt(scope, agentId) {
  const outPath = `test/ai-reviews/${agentId}/${scope}.md`;
  return [
    `Perform an AI security review of the triauth-js library for the scope "${scope}".`,
    `Follow test/ai-reviews/_harness/GUIDE.md EXACTLY — read it first, then the source files it lists for this scope, the README's Best Practices and Security Considerations section, and the matching README section.`,
    `Read the existing review at ${outPath} if present and obey the finding-ID reuse rule (update by ID, never duplicate or renumber).`,
    `Write your review to ${outPath}.`,
    `You own only: scope, status, summary, and the ## Findings section. Leave the other frontmatter fields as placeholders — they are stamped after you. NEVER add, remove, or alter a [reviewed] tag or any "Human review" note.`,
  ].join('\n');
}

function stampMetadata(text, { agent, scope, params }) {
  const { data, body } = parse(text);
  const stamped = {
    model: agent.model,
    model_id: agent.model_id,
    scope,
    lib_version: pkg.version,
    commit: headCommit,
    reviewed_at: today,
    status: computeStatus(body),          // derived from findings, not the model's assertion
    summary: data.summary ?? '',
    settings: { ...params },
  };
  return serialize(stamped, body);
}

function elapsedSince(started) {
  const s = Math.round((Date.now() - started) / 1000);
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m${String(s % 60).padStart(2, '0')}s`;
}

// ---- plan -----------------------------------------------------------------
// One entry per (agent × scope). Each agent CLI is probed once up front, so a missing CLI skips
// that agent as a whole, and the committed finding IDs are captured before anything runs.
const runs = [];
let skipped = 0;
for (const agent of agents) {
  const probe = spawnSync(agent.id, ['--version'], { encoding: 'utf8' });
  if (probe.error || probe.status !== 0) {
    console.warn(`⚠ '${agent.id}' CLI not found on PATH — skipping ${agent.model}.`);
    skipped++;
    continue;
  }
  const params = { ...agent.params, ...(opts.effort ? { effort: opts.effort } : {}) };
  mkdirSync(join(repoRoot, 'test', 'ai-reviews', agent.id), { recursive: true });
  for (const scope of scopes) {
    const relPath = `test/ai-reviews/${agent.id}/${scope}.md`;
    const absPath = join(repoRoot, relPath);
    runs.push({
      agent, scope, params, relPath, absPath,
      before: existsSync(absPath) ? readFileSync(absPath, 'utf8') : null,   // restored when the run fails
      beforeIds: findingIds(committedVersion(relPath)),
    });
  }
}
if (!runs.length) { console.log(`Nothing to run: ${skipped} agent(s) skipped.`); process.exit(0); }

// ---- run ------------------------------------------------------------------
// The agent CLIs share the terminal only through their one-line results below. Each CLI's own
// output goes to <logDir>/<agent>-<scope>.log (stderr as it happens, stdout appended at exit),
// and stdin is closed so the concurrent processes never compete for the keyboard.
const logDir = mkdtempSync(join(tmpdir(), 'ai-review-'));

// Launch one agent CLI; resolves with its captured stdout plus a short problem note (null when the
// CLI exited cleanly and its adapter's `verify` accepted the run).
function launch(run) {
  return new Promise(done => {
    const fd = openSync(run.logPath, 'w');
    const [bin, args] = run.agent.cmd(buildPrompt(run.scope, run.agent.id), run.params);
    const child = spawn(bin, args, { cwd: repoRoot, env: { ...process.env, ...run.agent.env }, stdio: ['ignore', 'pipe', fd] });
    closeSync(fd);                                      // the child holds its own copy
    const chunks = [];
    child.stdout.on('data', c => chunks.push(c));
    child.on('error', err => done({ stdout: '', problem: `failed to start (${err.message})` }));
    child.on('close', (code, signal) => {
      const stdout = Buffer.concat(chunks).toString('utf8');
      const stderr = readFileSync(run.logPath, 'utf8');
      appendFileSync(run.logPath, stdout);
      const problem = code !== 0 ? (signal ? `killed by ${signal}` : `exited ${code}`)
        : run.agent.verify?.({ stdout, stderr }, run.agent.model_id) ?? null;
      done({ stdout, problem });
    });
  });
}

// One review end to end: launch, wait, verify, stamp, count new findings, report a single line.
// A failed run puts the review file back exactly as it was before the run.
async function review(run) {
  run.logPath = join(logDir, `${run.agent.id}-${run.scope}.log`);
  const started = Date.now();
  const { problem } = await launch(run);
  const label = `${run.agent.model} → ${run.scope} (${elapsedSince(started)})`;
  if (problem || !existsSync(run.absPath)) {
    const touched = existsSync(run.absPath) && readFileSync(run.absPath, 'utf8') !== run.before;
    if (touched) run.before === null ? rmSync(run.absPath, { force: true }) : writeFileSync(run.absPath, run.before);
    const why = problem ? `${run.agent.id} ${problem}` : `${run.relPath} was not written`;
    console.warn(`✗ ${label}: ${why}${touched ? `, ${run.relPath} restored` : ''}. Log: ${run.logPath}`);
    return;
  }
  const text = stampMetadata(readFileSync(run.absPath, 'utf8'), run);
  writeFileSync(run.absPath, text);
  run.written = true;
  const newIds = [...findingIds(text)].filter(id => !run.beforeIds.has(id));
  console.log(`✓ ${label}: wrote ${run.relPath}, status: ${parse(text).data.status}, ${newIds.length} new finding(s)`);
}

console.log(`Running ${runs.length} review(s)${jobs < runs.length ? `, ${jobs} at a time` : ' all at once'}. Logs: ${logDir}`);
const queue = [...runs];
await Promise.all(Array.from({ length: Math.min(jobs, runs.length) }, async () => {
  for (let run = queue.shift(); run; run = queue.shift()) await review(run);
}));

const written = runs.filter(run => run.written).length;
console.log(`\nDone: ${written} review(s) written, ${runs.length - written} failed, ${skipped} agent(s) skipped. Review 'git diff test/ai-reviews/' and commit.`);
