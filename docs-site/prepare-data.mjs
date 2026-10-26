#!/usr/bin/env node
// Builds the report's chart data and public raw JSON from the benchmark evidence in
// server/test/benchmarks/results, then checks that the pages quote the same numbers.
// Rerun after the evidence changes:  node prepare-data.mjs
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const RESULTS = path.resolve(HERE, '../server/test/benchmarks/results');
const SRC = path.join(HERE, 'src');
const DATA = path.join(SRC, 'data');
const RAW = path.join(DATA, 'raw');
const BASE_REF = '256eb55dbe92ac77e02794442f9487e88ffed2b1';
const CPU = '13th Gen Intel(R) Core(TM) i5-13420H';

const read = (name) => JSON.parse(fs.readFileSync(path.join(RESULTS, `${name}.json`), 'utf8'));
const write = (file, value) => fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
const median = (values) => {
  const s = [...values].sort((a, b) => a - b);
  const m = s.length >> 1;
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};
const near = (a, b, msg) => assert.ok(Math.abs(a - b) < 1e-9, `${msg}: ${a} != ${b}`);
const round = (n, digits) => Number(n.toFixed(digits));

// ---------- sanitize ----------

const PRIVATE = [/\/home\/[^/\s"']+/g, /\bunix:\/\/\/tmp\/[^\s"']+/g, /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, /\b[a-z0-9-]+\.dpdns\.org\b/g, /\byvm@/g];
const REPLACE = ['~', 'unix:///<local-docker-socket>', '<lan-host>', '<private-origin>', ''];
const scrub = (value) => {
  if (typeof value === 'string') return PRIVATE.reduce((s, re, i) => s.replace(re, REPLACE[i]), value);
  if (Array.isArray(value)) return value.map(scrub);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).filter(([k]) => k !== 'hostname').map(([k, v]) => [k, scrub(v)]));
  }
  return value;
};
const numbers = (value) =>
  typeof value === 'number' ? [value] : value && typeof value === 'object' ? Object.values(value).flatMap(numbers) : [];
const assertPublic = (name, value) => {
  const text = JSON.stringify(value);
  for (const re of [/\/home\//, /\/tmp\//, /\b(?:\d{1,3}\.){3}\d{1,3}\b/, /dpdns/, /yvm/, /"hostname"/, /credential/i, /admin-credentials/, /curl-auth/]) {
    assert.ok(!re.test(text), `${name}: public JSON still matches ${re}`);
  }
};

// ---------- evidence ----------

const person = read('person-linux-db');
const bcrypt = read('bcrypt-local');
const media = read('media-local');
const hosted = read('hosted-network');
const deployment = read('deployment');
const upload = read('upload-check-linux-summary');
const uploadRuns = upload.runFiles.map((name) => read(name.replace(/\.json$/, '')));
assert.equal(uploadRuns.length, 3);
assert.equal(upload.results.length, 9);
assert.ok(upload.results.every((row) => row.candidateMedianMs < row.baselineMedianMs));
for (const [index, row] of upload.results.entries()) {
  const samples = uploadRuns.map((run) => {
    const measured = run.results[index];
    assert.equal(measured.count, row.count);
    assert.equal(measured.duplicateFraction, row.duplicateFraction);
    assert.equal(run.release.commit, upload.baselineRelease.commit);
    assert.equal(run.candidate.methodSha256, upload.candidate.methodSha256);
    return Object.fromEntries(measured.medians.map((item) => [item.version, item.elapsedMs]));
  });
  near(row.baselineMedianMs, median(samples.map((s) => s.baseline)), 'upload baseline');
  near(row.candidateMedianMs, median(samples.map((s) => s.candidate)), 'upload candidate');
  near(row.medianReductionPercent, median(samples.map((s) => 100 * (1 - s.candidate / s.baseline))), 'upload reduction');
}

for (const d of [person, bcrypt, media]) assert.equal(d.baselineRef, BASE_REF, 'baseline ref');
assert.equal(person.platform.client.cpu, CPU);
assert.equal(bcrypt.platform.cpu, CPU);
assert.equal(media.platform.cpu, CPU);

// Face query: recompute every median from the samples.
const faces = person.results.map((r) => {
  const get = (list, v) => list.find((x) => x.version === v);
  const out = { eligible: r.eligibleFaces };
  for (const v of ['original', 'modified']) {
    const samples = r.samples.filter((s) => s.version === v).map((s) => s.elapsedMs);
    assert.equal(samples.length, person.method.measuredRounds, `${r.eligibleFaces} ${v} sample count`);
    near(median(samples), get(r.medians, v).medianMs, `${r.eligibleFaces} ${v} median`);
    out[v] = { medianMs: median(samples), rows: get(r.returned, v).rows, bytes: get(r.returned, v).approximateJsonBytes };
  }
  return out;
});
assert.deepEqual(faces.map((f) => f.eligible), [1, 1000, 10000]);
assert.deepEqual(faces.map((f) => f.original.rows), [1, 1000, 10000]);
assert.deepEqual(faces.map((f) => f.modified.rows), [1, 1, 1]);
assert.ok(person.method.transfer.includes('not PostgreSQL wire bytes'));

// bcrypt: event-loop delay and completion counts.
const bc = {};
for (const v of ['original', 'modified']) {
  const rows = bcrypt.results.filter((r) => r.version === v);
  assert.equal(rows.length, bcrypt.method.rounds);
  assert.ok(rows.every((r) => r.completedAtCheckpoint === (v === 'original' ? 4 : 0)), `${v} completion counts`);
  bc[v] = { checkpoint: median(rows.map((r) => r.checkpointMs)), total: median(rows.map((r) => r.totalMs)), rounds: rows };
  near(bc[v].checkpoint, bcrypt.summary[v].medianCheckpointMs, `bcrypt ${v} checkpoint`);
  near(bc[v].total, bcrypt.summary[v].medianTotalMs, `bcrypt ${v} total`);
}
assert.equal(bcrypt.method.input.bcryptCost, 10);
assert.equal(bcrypt.method.input.comparisonsPerBatch, 4);

// Media: fs.access calls and per-scenario medians.
const SCENARIOS = { thumbnail: 'Thumbnail (200)', cached: 'Conditional (304)', range: 'Range (206)' };
const mediaRows = Object.keys(SCENARIOS).map((scenario) => {
  const out = { scenario };
  for (const name of ['original', 'current']) {
    const samples = media.samples.filter((s) => s.name === name && s.scenario === scenario);
    assert.equal(samples.length, media.method.rounds, `${name} ${scenario} samples`);
    const summary = media.summary.find((s) => s.name === name && s.scenario === scenario);
    near(median(samples.map((s) => s.ms)), summary.medianMsPer200Requests, `${name} ${scenario} median`);
    assert.equal(summary.requests, 1000);
    assert.equal(samples.reduce((n, s) => n + s.accessCalls, 0), summary.accessCalls);
    out[name] = { medianMs: summary.medianMsPer200Requests, accessCalls: summary.accessCalls };
  }
  assert.equal(out.original.accessCalls, 1000);
  assert.equal(out.current.accessCalls, 0);
  return out;
});
// The thumbnail median got slower and the other two got faster; the page has to say so.
assert.ok(mediaRows[0].current.medianMs > mediaRows[0].original.medianMs);
assert.ok(mediaRows[1].current.medianMs < mediaRows[1].original.medianMs);
assert.ok(mediaRows[2].current.medianMs < mediaRows[2].original.medianMs);

// Hosted smoke test and checks.
assert.equal(hosted.rateLimitBytesPerSecond, 128 * 1024);
assert.deepEqual(hosted.results.map((r) => r.http_code), [200, 304, 206]);
assert.equal(hosted.results[0].size_download, hosted.originalBytes);
const c = deployment.checks;
assert.deepEqual([c.focusedUnitTestsPassed, c.personPostgresTestsPassed, c.workerTestsPassed], [384, 40, 2]);
assert.equal(c.focusedUnitTestsPassed + c.personPostgresTestsPassed + c.workerTestsPassed, 426);
assert.equal(c.typescript, 'passed');
assert.equal(c.productionBuild, 'passed');
assert.match(c.opusReview, /Caching404 finding fixed and re-reviewed/);

// ---------- public raw JSON ----------

const publicDeployment = {
  note: 'Sanitized summary. The temporary test deployment and its proxy have been stopped; host, paths and URLs are omitted.',
  baselineRef: BASE_REF,
  sourceVersion: deployment.sourceVersion,
  machineLearningEnabled: deployment.machineLearningEnabled,
  deployedCompiledSha256: deployment.deployedCompiledSha256,
  checks: deployment.checks,
  publicSmoke: Object.fromEntries(Object.entries(deployment.publicSmoke).filter(([k]) => k !== 'url')),
  nativeCodecs: deployment.nativeCodecs,
};
const raw = {
  'person-linux-db': person,
  'bcrypt-local': bcrypt,
  'media-local': media,
  'hosted-network': { ...hosted, origin: 'temporary test deployment (stopped)' },
  deployment: publicDeployment,
  'upload-check-linux-summary': upload,
  ...Object.fromEntries(upload.runFiles.map((name, index) => [name.replace(/\.json$/, ''), uploadRuns[index]])),
};
fs.rmSync(RAW, { recursive: true, force: true });
fs.mkdirSync(RAW, { recursive: true });
for (const [name, value] of Object.entries(raw)) {
  const clean = scrub(value);
  assertPublic(name, clean);
  // Sanitizing must only touch text: every measured number survives unchanged.
  assert.deepEqual(numbers(clean), numbers(value), `${name}: numbers changed while sanitizing`);
  write(path.join(RAW, `${name}.json`), clean);
}

// ---------- chart specs ----------

const SERIES = ['Before (256eb55)', 'After'];
const charts = {
  'face-latency': {
    type: 'line',
    title: 'getRandomFace median latency by group size',
    subtitle: `Median of ${person.method.measuredRounds} rounds after ${person.method.warmupRounds} warm-ups. Lower is better.`,
    unit: 'ms',
    better: 'lower',
    xLabel: 'Eligible faces in the group',
    x: faces.map((f) => f.eligible.toLocaleString('en-US')),
    series: [
      { name: SERIES[0], values: faces.map((f) => round(f.original.medianMs, 2)) },
      { name: SERIES[1], values: faces.map((f) => round(f.modified.medianMs, 2)) },
    ],
  },
  'bcrypt-delay': {
    type: 'compare',
    title: 'Four bcrypt checks at cost 10, median of 6 rounds',
    better: 'lower',
    unit: 'ms',
    labels: ['compareSync (before)', 'compare (after)'],
    rows: [
      { label: 'Delay before a queued callback runs', before: round(bc.original.checkpoint, 2), after: round(bc.modified.checkpoint, 2) },
      { label: 'Time until all four checks finish', before: round(bc.original.total, 2), after: round(bc.modified.total, 2) },
    ],
  },
  'bcrypt-rounds': {
    type: 'bar',
    title: 'Event-loop callback delay in each round',
    unit: 'ms',
    better: 'lower',
    xLabel: 'Round',
    x: bc.original.rounds.map((r) => `Round ${r.round + 1}`),
    series: [
      { name: SERIES[0], values: bc.original.rounds.map((r) => round(r.checkpointMs, 2)) },
      { name: SERIES[1], values: bc.modified.rounds.map((r) => round(r.checkpointMs, 2)) },
    ],
  },
  'media-access': {
    type: 'compare',
    title: 'fs.access calls per 1,000 media requests',
    better: 'lower',
    labels: ['Before', 'After'],
    rows: mediaRows.map((r) => ({ label: SCENARIOS[r.scenario], before: r.original.accessCalls, after: r.current.accessCalls })),
  },
  'media-latency': {
    type: 'bar',
    title: 'Median time per 200 loopback requests',
    subtitle: 'Median of 5 rounds. The spread between rounds is larger than these differences.',
    unit: 'ms',
    better: 'lower',
    x: mediaRows.map((r) => SCENARIOS[r.scenario]),
    series: [
      { name: SERIES[0], values: mediaRows.map((r) => round(r.original.medianMs, 1)) },
      { name: SERIES[1], values: mediaRows.map((r) => round(r.current.medianMs, 1)) },
    ],
  },
};
for (const f of fs.readdirSync(DATA)) if (f.endsWith('.json')) fs.rmSync(path.join(DATA, f));
for (const [name, spec] of Object.entries(charts)) write(path.join(DATA, `${name}.json`), spec);

// Generate the latest-release table from the same checked evidence that is published below.
const uploadRows = upload.results.map((row) => `<tr><td class="num">${row.count.toLocaleString('en-US')}</td><td class="num">${row.duplicateFraction * 100}%</td><td class="num">${row.baselineMedianMs.toFixed(3)}</td><td class="num">${row.candidateMedianMs.toFixed(3)}</td><td class="num">${row.medianReductionPercent.toFixed(1)}%</td></tr>`).join('\n');
fs.writeFileSync(path.join(SRC, 'release-comparison.html'), `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Upload preflight against Immich ${upload.baselineRelease.tag_name} · OpenFrame</title>
<meta name="description" content="Measured elapsed method time for upload duplicate checks against the latest stable Immich release. Includes raw samples and measurement limits.">
<link rel="icon" href="assets/favicon.svg" type="image/svg+xml"><link rel="stylesheet" href="assets/site.css">
<script src="site.config.js"></script><script src="assets/site.js" defer></script>
</head><body><main class="doc-main">
<header class="doc-head"><p class="eyebrow cap">Latest-release comparison · upload preflight CPU</p>
<h1>Decode upload checksums once</h1>
<p class="lede">OpenFrame reuses decoded checksums when matching duplicate uploads. This removes a second decode for each file. The table measures that method's CPU work against Immich ${upload.baselineRelease.tag_name}, not file-transfer speed.</p>
<div class="doc-meta"><span>Measured <b>2026-10-26</b></span><span>Linux test bench</span><span class="badge warn">In-memory repository</span></div></header>
<article class="doc-body"><h2>Measured results</h2>
<p>Median of three process medians, in milliseconds per batch. All nine measured workloads had lower elapsed method time in the candidate. This is evidence for this method and these workloads only.</p>
<table><thead><tr><th>Files</th><th>Duplicates</th><th>Immich, ms</th><th>OpenFrame, ms</th><th>Method time reduction</th></tr></thead><tbody>${uploadRows}</tbody></table>
<h2>Method and versions</h2>
<p>The baseline is the method shipped in the official <a href="${upload.baselineRelease.html_url}">Immich ${upload.baselineRelease.tag_name} release</a>, commit <code>${upload.baselineRelease.commit}</code>. The candidate method comes from OpenFrame commit <code>${upload.candidate.head}</code> plus the exact patch and source hashes in the <a href="data/raw/upload-check-linux-summary.json">raw summary</a>.</p>
<p>Both methods run on the same Linux box with an AMD A4-9125 CPU, inside the same pinned upstream server image with Node ${uploadRuns[0].runtime.node}. Each process uses five warmup rounds and 30 measured rounds with alternating execution order. The repository is in memory. Each run includes 100, 1,000 and 10,000 checksums with 0%, 50% and 100% duplicates. Raw process files contain hardware, image digest, workload settings, individual samples and correctness checks.</p>
<p>Commands and the benchmark harness are in <a href="https://github.com/Ghoststack0/OpenFrame/tree/HEAD/server/test/benchmarks">server/test/benchmarks</a>. The preparation script takes an output directory and compiles the actual working-tree method. The run script verifies the upstream release and image before executing the prepared benchmark on the Linux box.</p>
<h2>Limits and regressions</h2>
<div class="callout warn"><p class="cap">Not an end-to-end upload benchmark</p><p>This test excludes database queries, network transfer, storage writes, thumbnail generation and mobile clients. It cannot establish that OpenFrame as a whole is faster or has no regressions. Runs two and three overlapped dependency copying on the host. The observed process variation is not a confidence interval.</p></div>
<p>Correctness checks cover mixed hex and base64 encodings, repeated checksums, empty input, output order, duplicate rejection and trashed status. A baseline-versus-baseline control is retained in the repository. The separate HTTP deployment comparison is still in progress.</p>
<h2>Raw evidence</h2><ul>${upload.runFiles.map((name) => `<li><a href="data/raw/${name}">${name}</a></li>`).join('')}<li><a href="data/raw/upload-check-linux-summary.json">Summary, patch and source hashes</a></li></ul>
</article></main></body></html>\n`);

// ---------- pages quote the evidence ----------

const fix = (n, d) => n.toFixed(d);
const [f1, f1000, f10000] = faces;
const expected = {
  'performance.html': [
    `data-value="${fix(f10000.modified.medianMs, 1)}" data-before="${fix(f10000.original.medianMs, 1)}"`,
    `data-value="1" data-before="${f10000.original.rows}"`,
    `data-value="${fix(bc.modified.checkpoint, 2)}" data-before="${fix(bc.original.checkpoint, 1)}"`,
    `data-value="0" data-before="1000"`,
    ...faces.flatMap((f) => [
      `<td class="num">${fix(f.original.medianMs, 2)} ms</td><td class="num">${fix(f.modified.medianMs, 2)} ms</td>`,
      `<td class="num">${f.original.rows.toLocaleString('en-US')} → ${f.modified.rows}</td>`,
      `<td class="num">${f.original.bytes.toLocaleString('en-US')} → ${f.modified.bytes}</td>`,
    ]),
    `${fix(f1000.original.medianMs / f1000.modified.medianMs, 0)}×`,
    `${fix(f10000.original.medianMs / f10000.modified.medianMs, 0)}×`,
    ...mediaRows.map((r) => `<td class="num">${fix(r.original.medianMs, 1)} ms</td><td class="num">${fix(r.current.medianMs, 1)} ms</td>`),
    ...hosted.results.map((r) => `<td class="num">${r.http_code}</td><td class="num">${r.size_download.toLocaleString('en-US')}</td><td class="num">${fix(r.time_total, 2)} s</td>`),
    `${c.focusedUnitTestsPassed} unit`,
    `${c.personPostgresTestsPassed} PostgreSQL`,
    `${c.workerTestsPassed} proxy`,
  ],
  'methodology.html': [CPU, BASE_REF, ...['person-linux-db', 'bcrypt-local', 'media-local', 'hosted-network', 'deployment'].map((n) => `href="data/raw/${n}.json"`)],
  'release-comparison.html': [upload.baselineRelease.commit, upload.candidate.head, ...upload.runFiles.map((name) => `href="data/raw/${name}"`)],
  // The OpenFrame overview repeats two headline tiles and must quote them exactly.
  'index.html': [
    'href="release-comparison.html"',
    `${Math.min(...upload.results.map((row) => row.medianReductionPercent)).toFixed(1)}–${Math.max(...upload.results.map((row) => row.medianReductionPercent)).toFixed(1)}%`,
    `data-value="${fix(f10000.modified.medianMs, 1)}" data-before="${fix(f10000.original.medianMs, 1)}"`,
    `data-value="${fix(bc.modified.checkpoint, 2)}" data-before="${fix(bc.original.checkpoint, 1)}"`,
  ],
  'contributing.html': [],
};
for (const [page, snippets] of Object.entries(expected)) {
  const html = fs.readFileSync(path.join(SRC, page), 'utf8');
  for (const s of snippets) assert.ok(html.includes(s), `${page} is missing: ${s}`);
  // Guard against claims the evidence doesn't support.
  assert.ok(!/\d+× faster|(?:makes|made) immich \d|(?:uses|using) less (?:RAM|memory|bandwidth)|(?:RAM|memory|bandwidth) (?:reduced|reduction|savings?)/i.test(html), `${page} makes an unsupported claim`);
}
assert.ok(f1.original.medianMs > 0);

console.log(`ok: ${Object.keys(charts).length} charts, ${Object.keys(raw).length} raw files, ${Object.values(expected).flat().length} page checks`);
