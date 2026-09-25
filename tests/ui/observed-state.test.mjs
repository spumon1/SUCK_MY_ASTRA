// Unit test for observedState, the one piece of dashboard logic that can lie.
//
// Everything else in ui.html renders a number the server sent. This function
// decides what a cell CLAIMS about the upstream right now, from observations
// that may be stale or may not exist -- and the wrong answer here is not a
// cosmetic bug, it is the page telling an operator "normal" about a bucket it
// has been blind to for the last hour.
//
// It is a pure function, so it can be tested without a DOM. The source is
// sliced out of ui.html between the section marker and renderMatrix rather
// than duplicated, so this cannot silently drift from what ships.
//
//   node tests/ui/observed-state.test.mjs

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, '..', '..', 'go', 'ui.html'), 'utf8');

const START = '/* ---------------------------- 服务态 ---------------------------- */';
const END = 'function renderMatrix(';
const from = html.indexOf(START);
const to = html.indexOf(END, from);
if (from < 0 || to < 0) {
  throw new Error('could not find the 服务态 section in ui.html; the markers moved');
}
const source = html.slice(from, to);
for (const name of ['OBS_UNKNOWN_MS', 'OBS_STALE_MS', 'fmtAgo', 'obsKindName', 'obs24h', 'observedState']) {
  if (!source.includes(name)) throw new Error(`sliced section is missing ${name}`);
}
const observedState = new Function(source + '\nreturn observedState;')();

const MIN = 60 * 1000;
const ago = (m) => new Date(Date.now() - m * MIN).toISOString();

let failures = 0;
function check(name, got, wantCls, wantLabelPart) {
  const ok = got.cls === wantCls && (!wantLabelPart || got.label.includes(wantLabelPart));
  if (!ok) {
    failures++;
    console.error(`FAIL ${name}\n  got  cls=${got.cls} label=${JSON.stringify(got.label)}\n  want cls=${wantCls}${wantLabelPart ? ` label~${JSON.stringify(wantLabelPart)}` : ''}`);
  } else {
    console.log(`ok   ${name}`);
  }
}

// No observations at all is NOT normal. A bucket nobody has sent traffic to
// must never render green.
check('no observations', observedState({ ready: true }, false), 'obs-none', '无观测');
check('observed absent but ready', observedState({ ready: true, observed: null }, false), 'obs-none', '无观测');

// Older than the unknown window: the bucket is idle, not healthy.
check('idle for three hours', observedState({
  ready: true,
  observed: { last_at: ago(190), last_kind: 'normal', last_signed_kind: 'normal', last_signed_at: ago(190) },
}, false), 'obs-none', '未知');

// The alarm outranks everything: we supplied a valid template and were
// degraded anyway.
check('injected and still limited', observedState({
  ready: true,
  observed: {
    last_at: ago(0), last_kind: 'limited', last_wrote: true, injected_limited: 97,
    last_signed_kind: 'limited', last_signed_at: ago(0), last_signed_wrote: true,
  },
}, false), 'obs-alarm', '模板失效');

// A fresh unprompted reading speaks for right now.
check('fresh natural normal', observedState({
  ready: true,
  observed: {
    last_at: ago(2), last_kind: 'normal', last_wrote: false, natural_normal: 161,
    last_natural_kind: 'normal', last_natural_at: ago(2),
    last_signed_kind: 'normal', last_signed_at: ago(2), last_signed_wrote: false,
  },
}, false), 'obs-ok', '正常 (292)');

check('fresh natural limited', observedState({
  ready: false,
  observed: {
    last_at: ago(1), last_kind: 'limited', last_wrote: false, natural_limited: 1076,
    last_natural_kind: 'limited', last_natural_at: ago(1),
    last_signed_kind: 'limited', last_signed_at: ago(1), last_signed_wrote: false,
  },
}, false), 'obs-bad', '受限 (312)');

// A 292 signed on a request we injected into is still the upstream saying it
// serves this account normally -- the most direct evidence there is. Ageing
// only the unprompted readings would file it as no evidence and show a healthy
// bucket as blind while it holds the proof.
check('injected and signed a fresh 292', observedState({
  ready: true,
  observed: {
    last_at: ago(1), last_kind: 'normal', last_wrote: true, injected_normal: 8,
    last_signed_kind: 'normal', last_signed_at: ago(1), last_signed_wrote: true,
  },
}, false), 'obs-ok', '正常 (292)');

// An unrecognised length must never render as 292. If OpenAI changes the token
// format every response becomes "other", and a green wall in that moment is
// the worst thing this panel could do.
check('unrecognised length is not green', observedState({
  ready: false,
  observed: {
    last_at: ago(1), last_kind: 'other', last_len: 340, last_wrote: false, natural_other: 55,
    last_natural_kind: 'other', last_natural_at: ago(1),
    last_signed_kind: 'other', last_signed_at: ago(1), last_signed_wrote: false,
  },
}, false), 'obs-bad', '未知格式 (340)');

// THE regression this file exists for. A bucket holding a template is injected
// on every request, so the upstream signs nothing and the last reading ages
// out. It must read as blind, never as the hour-old "normal".
check('blind while injecting', observedState({
  ready: true,
  observed: {
    last_at: ago(0), last_kind: 'silent', last_wrote: true, injected_silent: 806,
    natural_normal: 12,
    last_signed_kind: 'normal', last_signed_at: ago(47), last_signed_wrote: false,
  },
}, false), 'obs-blind', '注入中 · 盲区');

// Same bucket under dry_run. The template is held but never sent, so the
// silence is the upstream's own doing and calling it our blind spot is a lie
// -- in precisely the mode an operator picks in order to watch without
// touching anything.
check('dry_run holds a template but injects nothing', observedState({
  ready: true,
  observed: {
    last_at: ago(0), last_kind: 'silent', last_wrote: false, natural_normal: 12,
    last_signed_kind: 'normal', last_signed_at: ago(47), last_signed_wrote: false,
  },
}, true), 'obs-blind', '有模板 · 未注入');

// A ready bucket with no requests at all is not a blind spot either. Nothing
// is being injected because nothing is being sent.
check('ready but no traffic', observedState({
  ready: true,
  observed: {
    last_at: ago(38), last_kind: 'normal', last_wrote: false, natural_normal: 12,
    last_signed_kind: 'normal', last_signed_at: ago(38), last_signed_wrote: false,
  },
}, false), 'obs-blind', '无流量');

// Traffic flowing, bucket empty, upstream silent: report the last reading and
// say it is stale. Not blind -- nothing is being injected, so the silence is
// not our doing.
check('stale with an empty bucket', observedState({
  ready: false,
  observed: {
    last_at: ago(1), last_kind: 'silent', last_wrote: false, natural_limited: 11,
    last_signed_kind: 'limited', last_signed_at: ago(38), last_signed_wrote: false,
  },
}, false), 'obs-blind', '陈旧');

// The sample size rides along, because 3 observations and 4237 observations
// are not the same claim.
const withN = observedState({
  ready: true,
  observed: {
    last_at: ago(1), last_kind: 'normal', last_wrote: false, natural_normal: 40, natural_limited: 2,
    last_signed_kind: 'normal', last_signed_at: ago(1), last_signed_wrote: false,
  },
}, false);
if (!withN.label.includes('n=42')) {
  failures++;
  console.error(`FAIL sample size in label\n  got ${JSON.stringify(withN.label)}, want it to carry n=42`);
} else {
  console.log('ok   sample size in label');
}

// The 24h rollup is the only thing on the page that can answer "is this worse
// than it was yesterday". Lifetime totals cannot.
const with24h = observedState({
  ready: true,
  observed: {
    last_at: ago(1), last_kind: 'limited', last_wrote: false, natural_limited: 900,
    last_signed_kind: 'limited', last_signed_at: ago(1), last_signed_wrote: false,
    recent_24h: { natural_normal: 3, natural_limited: 411 },
  },
}, false);
if (!with24h.title.includes('近 24h 自然观测：正常 3 · 受限 411')) {
  failures++;
  console.error(`FAIL 24h rollup in tooltip\n  got ${JSON.stringify(with24h.title)}`);
} else {
  console.log('ok   24h rollup in tooltip');
}

// Every state must carry an explanation; a bare colour is not a finding.
for (const [name, cell, dry] of [
  ['none', { ready: true }, false],
  ['alarm', { ready: true, observed: { last_at: ago(0), last_kind: 'limited', last_wrote: true, last_signed_kind: 'limited', last_signed_at: ago(0), last_signed_wrote: true } }, false],
  ['blind', { ready: true, observed: { last_at: ago(0), last_kind: 'silent', last_wrote: true, last_signed_at: ago(47), last_signed_kind: 'normal' } }, false],
  ['dry_run', { ready: true, observed: { last_at: ago(0), last_kind: 'silent', last_wrote: false, last_signed_at: ago(47), last_signed_kind: 'normal' } }, true],
  ['other', { ready: false, observed: { last_at: ago(1), last_kind: 'other', last_len: 340, last_signed_kind: 'other', last_signed_at: ago(1) } }, false],
  ['no traffic', { ready: true, observed: { last_at: ago(40), last_kind: 'normal', last_signed_kind: 'normal', last_signed_at: ago(40) } }, false],
]) {
  const got = observedState(cell, dry);
  if (!got.title || got.title.length < 20) {
    failures++;
    console.error(`FAIL ${name} has no usable tooltip: ${JSON.stringify(got.title)}`);
  }
}

console.log(failures ? `\n${failures} failure(s)` : '\nall observedState checks passed');
process.exit(failures ? 1 : 0);
