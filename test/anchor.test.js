// First-pull trust anchor: pinning the genesis fingerprint. All keys here are
// THROWAWAY TEST KEYS generated in memory at test time.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  verifyFeed, verifyFeedDetailed, anchorFingerprint, formatFingerprint, normalizePin, emptyFeed, applyFeed, emptyState, pull, serializeFeed
} from '../src/index.js';
import { testKey, buildFeed, signed, resignRaw, NOW } from './helpers.js';

const key = testKey();
const POLICY = { trustedPosters: ['U-GIGATRON'], now: NOW };

function codeOf(fn) {
  try {
    fn();
  } catch (e) {
    return e.code || e.message;
  }
  return 'NO_ERROR';
}

test('fingerprint: short human form is hf2: + 8 groups of 4 hex (128 bits)', () => {
  const feed = buildFeed(key, 1);
  const fp = anchorFingerprint(feed.genesis);
  assert.match(fp, /^[0-9a-f]{64}$/);
  const disp = formatFingerprint(fp);
  assert.match(disp, /^hf2:([0-9a-f]{4}-){7}[0-9a-f]{4}$/);
  assert.equal(normalizePin(disp), fp.slice(0, 32));
  assert.equal(normalizePin(' HF2:' + fp.slice(0, 32).toUpperCase().match(/.{4}/g).join(' ') + ' '), fp.slice(0, 32));
  assert.equal(normalizePin('hf2:abcd-ef01'), null, 'fewer than 128 bits is not accepted as a pin');
  assert.equal(normalizePin('hf1:' + fp), null);
});

test('pinned fingerprint match: short form, full hex and grouped form all verify', () => {
  const feed = buildFeed(key, 3);
  const { bytes, sig } = signed(key, feed);
  const fp = anchorFingerprint(feed.genesis);
  for (const pin of [formatFingerprint(fp), fp, formatFingerprint(fp, 64)]) {
    const v = verifyFeedDetailed(bytes, sig, pin);
    assert.equal(v.pinKind, 'fingerprint');
    assert.equal(v.fingerprint, fp);
    assert.equal(v.feed.head.seq, 3);
    assert.deepEqual(v.warnings, []);
  }
});

test('pinned fingerprint mismatch: a different valid feed is refused', () => {
  const real = buildFeed(key, 2);
  const pin = formatFingerprint(anchorFingerprint(real.genesis));
  const attacker = testKey();
  const fake = buildFeed(attacker, 2); // same feed_id, perfectly valid, attacker key
  const { bytes, sig } = signed(attacker, fake);
  assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_ANCHOR_MISMATCH');
  // A pin that differs only in the last hex digit also fails.
  const fp = anchorFingerprint(real.genesis);
  const off = fp.slice(0, 31) + (fp[31] === '0' ? '1' : '0');
  const r = signed(key, real);
  assert.equal(codeOf(() => verifyFeed(r.bytes, r.sig, off)), 'HIVE_ANCHOR_MISMATCH');
});

test('fingerprint commits to the recovery digest; a genesis-key-only pin does not (and warns)', () => {
  const rec = testKey();
  const honest = emptyFeed('test-feed', key.publicKey, NOW, { recoveryPubkey: rec.publicKey });
  const pin = anchorFingerprint(honest.genesis);
  // Thief of the genesis key builds a look-alike genesis with THEIR recovery key.
  const thiefRec = testKey();
  const lookalike = emptyFeed('test-feed', key.publicKey, NOW, { recoveryPubkey: thiefRec.publicKey });
  const { bytes, sig } = signed(key, lookalike);
  assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_ANCHOR_MISMATCH');
  const v = verifyFeedDetailed(bytes, sig, key.publicKey);
  assert.equal(v.pinKind, 'genesis-pubkey');
  assert.ok(v.warnings.some((w) => /genesis public key only/.test(w)));
});

test('genesis edited and file re-signed: fingerprint pin catches it', () => {
  const feed = buildFeed(key, 1);
  const pin = anchorFingerprint(feed.genesis);
  const evil = structuredClone(feed);
  evil.genesis.created = '2020-01-01T00:00:00.000Z';
  const { bytes, sig } = resignRaw(key, serializeFeed(evil));
  assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_ANCHOR_MISMATCH');
});

test('unpinned: refused by default, explicit opt-in verifies with a loud UNPINNED warning', () => {
  const feed = buildFeed(key, 2);
  const { bytes, sig } = signed(key, feed);
  for (const pin of [undefined, null, '']) assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_UNPINNED');
  const v = verifyFeedDetailed(bytes, sig, null, { allowUnpinned: true });
  assert.equal(v.pinKind, 'unpinned');
  assert.ok(v.warnings.some((w) => /^UNPINNED \(TOFU\)/.test(w) && w.includes(v.fingerprintDisplay)));
});

test('bad pin strings are rejected, not treated as unpinned', () => {
  const { bytes, sig } = signed(key, buildFeed(key, 1));
  for (const pin of ['hf2:abcd', 'not-a-pin', 'hf1:' + 'a'.repeat(64)]) {
    assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_BAD_PIN', pin);
  }
});

test('consumer state remembers the anchor; a different genesis is refused later', () => {
  const r = applyFeed(emptyState(), buildFeed(key, 1), POLICY);
  assert.equal(r.state.anchor, anchorFingerprint(buildFeed(key, 1).genesis));
  const other = buildFeed(testKey(), 2);
  assert.throws(() => applyFeed(r.state, other, POLICY), { code: 'HIVE_ANCHOR_CHANGED' });
});

function serve(get) {
  return new Promise((resolve) => {
    const srv = createServer((req, res) => {
      const cur = get();
      if (req.url === '/feed.json') res.writeHead(200).end(cur.bytes);
      else if (req.url === '/feed.json.sig') res.writeHead(200).end(cur.sig);
      else res.writeHead(404).end();
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, base: 'http://127.0.0.1:' + srv.address().port }));
  });
}

test('pull: refuses without a pin; TOFU opt-in saves the anchor, which then pins later pulls', async () => {
  let cur = signed(key, buildFeed(key, 2));
  const { srv, base } = await serve(() => cur);
  try {
    const opts = { url: base + '/feed.json', policy: POLICY, allowHttp: true };
    await assert.rejects(pull({ ...opts, state: emptyState() }), { code: 'HIVE_UNPINNED' });
    const r1 = await pull({ ...opts, state: emptyState(), allowUnpinned: true });
    assert.ok(r1.warnings.some((w) => /UNPINNED/.test(w)));
    assert.equal(r1.state.anchor, anchorFingerprint(buildFeed(key, 2).genesis));
    // Host swapped to an attacker feed: the saved anchor refuses it, even
    // though allowUnpinned is still set.
    const attacker = testKey();
    cur = signed(attacker, buildFeed(attacker, 3));
    await assert.rejects(pull({ ...opts, state: { ...r1.state, etag: null }, allowUnpinned: true }), { code: 'HIVE_ANCHOR_MISMATCH' });
  } finally {
    srv.close();
  }
});

test('pull: pinned fingerprint accepts the right feed and refuses a wrong one', async () => {
  const feed = buildFeed(key, 2);
  const pin = formatFingerprint(anchorFingerprint(feed.genesis));
  let cur = signed(key, feed);
  const { srv, base } = await serve(() => cur);
  try {
    const opts = { url: base + '/feed.json', policy: POLICY, allowHttp: true, pin };
    const r = await pull({ ...opts, state: emptyState() });
    assert.equal(r.accepted.length, 2);
    assert.equal(r.fingerprintDisplay, pin);
    const attacker = testKey();
    cur = signed(attacker, buildFeed(attacker, 2));
    await assert.rejects(pull({ ...opts, state: emptyState() }), { code: 'HIVE_ANCHOR_MISMATCH' });
  } finally {
    srv.close();
  }
});
