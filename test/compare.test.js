// Peer history comparison. Every key is a THROWAWAY TEST KEY generated at
// test time and never stored in the repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  emptyFeed, appendEvent, makeView, serializeView, parseView, compareViews, comparePeers, rotateKey, anchorFingerprint,
  formatFingerprint, serializeFeed, signFeedBytes
} from '../src/index.js';
import { testKey, NOW } from './helpers.js';

const T0 = NOW.getTime() - 3600000;
const at = (i) => new Date(T0 + i * 60000);

function grow(feed, priv, from, to, tag = '', opts = {}) {
  let f = feed;
  for (let i = from; i <= to; i++) {
    f = appendEvent(f, priv, { type: 'task', id: 'ev-' + tag + i, ts: at(i).toISOString(), channel: 'c', poster_id: 'U-GIGATRON', text: 'event ' + tag + i }, { now: at(i), ...opts });
  }
  return f;
}

function base() {
  const key = testKey();
  const g = emptyFeed('cmp-test', key.publicKey, at(0));
  return { key, g };
}

function codeOf(fn) {
  try {
    fn();
  } catch (e) {
    return e.code || e.message;
  }
  return 'NO_ERROR';
}

test('equal histories are consistent', () => {
  const { key, g } = base();
  const f = grow(g, key.priv, 1, 5);
  const r = compareViews(makeView(f, { now: NOW }), makeView(f, { now: NOW, observer: 'peer-b' }));
  assert.equal(r.verdict, 'consistent');
  assert.equal(compareViews(makeView(g), makeView(g)).verdict, 'consistent');
});

test('prefix: a bot that is behind is reported as behind, not as a fork', () => {
  const { key, g } = base();
  const short = grow(g, key.priv, 1, 3);
  const long = grow(short, key.priv, 4, 7);
  const r = compareViews(makeView(short), makeView(long));
  assert.equal(r.verdict, 'prefix');
  assert.equal(r.behind, 'a');
  assert.equal(compareViews(makeView(long), makeView(short)).behind, 'b');
  assert.equal(compareViews(makeView(g), makeView(long)).verdict, 'prefix', 'empty feed is a prefix of everything');
  // Longer view with a pruned window that still covers the shorter head.
  const prunedLong = { ...long, events: long.events.slice(2) };
  assert.equal(compareViews(makeView(short), makeView(prunedLong)).verdict, 'prefix');
});

test('fork: same anchor, different histories, earliest divergence index reported', () => {
  const { key, g } = base();
  const common = grow(g, key.priv, 1, 3);
  const a = grow(common, key.priv, 4, 6, 'a');
  const b = grow(common, key.priv, 4, 8, 'b');
  const r = compareViews(makeView(a), makeView(b));
  assert.equal(r.verdict, 'fork');
  assert.equal(r.divergence_seq, 4);
  assert.equal(r.divergence_exact, true);
  // Same length, different head.
  const c = grow(common, key.priv, 4, 6, 'c');
  const r2 = compareViews(makeView(a), makeView(c));
  assert.equal(r2.verdict, 'fork');
  assert.equal(r2.divergence_seq, 4);
  // Fork at seq 1.
  const x = grow(g, key.priv, 1, 2, 'x');
  const y = grow(g, key.priv, 1, 2, 'y');
  const r3 = compareViews(makeView(x), makeView(y));
  assert.deepEqual([r3.verdict, r3.divergence_seq, r3.divergence_exact], ['fork', 1, true]);
  // Shorter view is NOT a prefix: its head is missing from the longer history.
  const shortA = grow(common, key.priv, 4, 4, 'a');
  assert.equal(compareViews(makeView(shortA), makeView(b)).verdict, 'fork');
});

test('fork with pruned windows gives an upper bound, not a false exact index', () => {
  const { key, g } = base();
  const common = grow(g, key.priv, 1, 2);
  const a = grow(common, key.priv, 3, 9, 'a', { keep: 4 }); // window 6..9
  const b = grow(common, key.priv, 3, 9, 'b');               // window 1..9
  const r = compareViews(makeView(a), makeView(b));
  assert.equal(r.verdict, 'fork');
  assert.equal(r.divergence_seq, 6);
  assert.equal(r.divergence_exact, false);
  // Non-overlapping windows cannot be judged.
  const far = grow(grow(g, key.priv, 1, 2), key.priv, 3, 20, '', { keep: 2 });
  const near = grow(g, key.priv, 1, 2);
  assert.equal(compareViews(makeView(near), makeView(far)).verdict, 'undetermined');
});

test('different genesis is reported as different feeds, even with the same feed_id', () => {
  const one = base();
  const two = base();
  const r = compareViews(makeView(grow(one.g, one.key.priv, 1, 3)), makeView(grow(two.g, two.key.priv, 1, 3)));
  assert.equal(r.verdict, 'different_genesis');
});

test('key history divergence is a fork; a rotation seen by both is consistent', () => {
  const { key, g } = base();
  const common = grow(g, key.priv, 1, 2);
  const k1 = testKey();
  const k2 = testKey();
  const ra = rotateKey(common, key.priv, k1.priv, { id: 'rot', ts: at(3).toISOString() }, { now: at(3) });
  const rb = rotateKey(common, key.priv, k2.priv, { id: 'rot', ts: at(3).toISOString() }, { now: at(3) });
  const va = makeView(ra);
  const vb = makeView(rb);
  assert.equal(compareViews(va, vb).verdict, 'fork');
  assert.equal(compareViews(va, vb).divergence_seq, 3);
  assert.equal(compareViews(va, vb).key_log.divergence_index, 0);
  assert.equal(compareViews(va, makeView(ra)).verdict, 'consistent');
  // Only key_log differs because both windows were pruned before the rotation.
  const pa = grow(ra, k1.priv, 4, 6, 'p', { keep: 1 });
  const pb = grow(rb, k2.priv, 4, 6, 'p', { keep: 1 });
  const vpa = makeView(pa);
  const vpb = { ...makeView(pb) };
  assert.equal(compareViews(vpa, vpb).verdict, 'fork');
});

test('view summary: digest catches edits, optional observer signature, strict shape', () => {
  const { key, g } = base();
  const f = grow(g, key.priv, 1, 3);
  const bot = testKey();
  const v = makeView(f, { observer: 'bot-a', signingKey: bot.priv, now: NOW });
  const parsed = parseView(serializeView(v));
  assert.equal(parsed.signed, true);
  assert.deepEqual(parsed.view, v);
  const unsigned = makeView(f, { now: NOW });
  assert.equal(parseView(serializeView(unsigned)).signed, false);
  const edited = serializeView({ ...v, head: { ...v.head, seq: 4 } });
  assert.notEqual(codeOf(() => parseView(edited)), 'NO_ERROR');
  const relabeled = { ...v, observer: 'bot-b' };
  assert.equal(codeOf(() => parseView(serializeView(relabeled))), 'HIVE_TAMPERED');
  const other = testKey();
  const stolen = makeView(f, { observer: 'bot-a', signingKey: other.priv, now: NOW });
  assert.equal(codeOf(() => parseView(serializeView({ ...v, sig: stolen.sig }))), 'HIVE_BAD_SIGNATURE');
  assert.equal(codeOf(() => parseView('{"format":"hive-feed/view-1"}')), 'HIVE_BAD_VIEW');
  assert.equal(codeOf(() => parseView('nope')), 'HIVE_BAD_VIEW');
  assert.equal(codeOf(() => parseView(JSON.stringify(v, null, 2))), 'HIVE_BAD_VIEW');
  // Fabricated view: hashes agree again after diverging.
  const ff = grow(g, key.priv, 1, 3, 'z');
  const fake = makeView(f);
  fake.window.hashes = [f.events[0].hash, ff.events[1].hash, f.events[2].hash];
  assert.match(String(codeOf(() => compareViews(makeView(f), fake))), /HIVE_BAD_VIEW/);
});

test('comparePeers: overall verdict, pin check, proven only for signed feeds on both sides', () => {
  const { key, g } = base();
  const common = grow(g, key.priv, 1, 3);
  const mine = makeView(grow(common, key.priv, 4, 5, 'a'));
  const pin = formatFingerprint(anchorFingerprint(g.genesis));
  const ok = comparePeers(mine, [{ name: 'p1', view: makeView(common), evidence: 'view-summary' }], { pin });
  assert.equal(ok.overall, 'consistent');
  assert.equal(ok.results[0].verdict, 'prefix');
  const forked = comparePeers(mine, [
    { name: 'p1', view: makeView(common), evidence: 'view-summary' },
    { name: 'p2', view: makeView(grow(common, key.priv, 4, 4, 'b')), evidence: 'signed-feed' }
  ], { pin, mineEvidence: 'signed-feed' });
  assert.equal(forked.overall, 'fork');
  assert.equal(forked.results[1].proven, true);
  const claim = comparePeers(mine, [{ name: 'p2', view: makeView(grow(common, key.priv, 4, 4, 'b')), evidence: 'view-summary' }], { pin, mineEvidence: 'signed-feed' });
  assert.equal(claim.results[0].proven, false);
  const other = base();
  assert.equal(comparePeers(mine, [{ name: 'x', view: makeView(other.g), evidence: 'view-summary' }]).overall, 'different_genesis');
  assert.equal(codeOf(() => comparePeers(mine, [], { pin: 'hf2:' + '0'.repeat(32) })), 'HIVE_ANCHOR_MISMATCH');
});

const cli = (args) => spawnSync(process.execPath, ['bin/hive-feed.js', ...args], { encoding: 'utf8' });
function writeSigned(dir, name, key, feed) {
  const p = join(dir, name);
  const bytes = serializeFeed(feed);
  writeFileSync(p, bytes);
  writeFileSync(p + '.sig', signFeedBytes(key.priv, Buffer.from(bytes)) + '\n');
  return p;
}

test('CLI view and compare: exit codes for consistent, prefix, fork, different genesis', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hive-cmp-'));
  const { key, g } = base();
  const common = grow(g, key.priv, 1, 3);
  const pin = formatFingerprint(anchorFingerprint(g.genesis));
  const mine = writeSigned(dir, 'mine.json', key, grow(common, key.priv, 4, 5, 'a'));
  const behind = writeSigned(dir, 'behind.json', key, common);
  const forked = writeSigned(dir, 'forked.json', key, grow(common, key.priv, 4, 6, 'b'));
  const o = base();
  const stranger = writeSigned(dir, 'stranger.json', o.key, grow(o.g, o.key.priv, 1, 2));

  const vOut = join(dir, 'behind.view.json');
  const v = cli(['view', '--feed', behind, '--anchor', pin, '--observer', 'peer-1', '--out', vOut]);
  assert.equal(v.status, 0, v.stderr);
  assert.equal(JSON.parse(readFileSync(vOut, 'utf8')).format, 'hive-feed/view-1');
  assert.equal(cli(['view', '--feed', behind, '--anchor', 'hf2:' + '0'.repeat(32)]).status, 1);

  const c1 = cli(['compare', '--anchor', pin, '--mine', mine, '--peer', vOut, '--peer', mine]);
  assert.equal(c1.status, 0, c1.stderr);
  const lines = c1.stdout.trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual(lines.map((l) => [l.verdict, l.behind, l.evidence]), [['prefix', 'peer', 'view-summary'], ['consistent', null, 'signed-feed']]);

  const c2 = cli(['compare', '--anchor', pin, '--mine', mine, '--peer', forked]);
  assert.equal(c2.status, 3);
  const f = JSON.parse(c2.stdout);
  assert.deepEqual([f.verdict, f.divergence_seq, f.divergence_exact, f.proven_by_signatures], ['fork', 4, true, true]);
  assert.match(c2.stderr, /evidence of equivocation/);

  assert.equal(cli(['compare', '--anchor', pin, '--mine', mine, '--peer', stranger]).status, 4);
  assert.equal(cli(['compare', '--anchor', pin, '--mine', stranger, '--peer', mine]).status, 1, 'my own view must match my pin');
  assert.equal(cli(['compare', '--anchor', pin, '--mine', mine]).status, 2);
});

test('CLI pull (default timeout/size flags omitted) --save-feed keeps the verified file, which view/compare can use', async () => {
  const { createServer } = await import('node:http');
  const { spawn } = await import('node:child_process');
  const dir = mkdtempSync(join(tmpdir(), 'hive-save-'));
  const { key, g } = base();
  const feed = grow(g, key.priv, 1, 3);
  const bytes = serializeFeed(feed);
  const sig = signFeedBytes(key.priv, Buffer.from(bytes)) + '\n';
  const srv = createServer((req, res) => {
    if (req.url === '/feed.json') res.writeHead(200).end(bytes);
    else if (req.url === '/feed.json.sig') res.writeHead(200).end(sig);
    else res.writeHead(404).end();
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const pin = formatFingerprint(anchorFingerprint(g.genesis));
  const saved = join(dir, 'saved.json');
  try {
    const status = await new Promise((resolve) => {
      const p = spawn(process.execPath, ['bin/hive-feed.js', 'pull', '--url', 'http://127.0.0.1:' + srv.address().port + '/feed.json', '--allow-http',
        '--anchor', pin, '--state', join(dir, 'state.json'), '--trusted', 'U-GIGATRON', '--save-feed', saved], { stdio: 'ignore' });

      p.on('exit', resolve);
    });
    assert.equal(status, 0);
  } finally {
    srv.close();
  }
  assert.equal(readFileSync(saved, 'utf8'), bytes);
  assert.equal(readFileSync(saved + '.sig', 'utf8'), sig);
  assert.equal(cli(['compare', '--anchor', pin, '--mine', saved, '--peer', saved]).status, 0);
});
