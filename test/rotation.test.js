// Key rotation, grace windows and recovery-key forced rotation. Every key is
// a THROWAWAY TEST KEY generated in memory at test time; none is stored.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyFeed, verifyFeedDetailed, anchorFingerprint, emptyFeed, appendEvent, rotateKey, recoverKey, applyFeed, emptyState,
  serializeFeedNdjson, signFeedBytes, publicKeyDigest, keyId, eventHash
} from '../src/index.js';
import { testKey, signed, forgeEvent, NOW } from './helpers.js';

const POLICY = { trustedPosters: ['U-GIGATRON', 'publisher'], now: NOW };
const T0 = NOW.getTime() - 60 * 60000;
const ts = (i) => new Date(T0 + i * 60000).toISOString();

function codeOf(fn) {
  try {
    fn();
  } catch (e) {
    return e.code || e.message;
  }
  return 'NO_ERROR';
}

function add(feed, priv, i, extra = {}) {
  return appendEvent(feed, priv, { type: 'task', id: 'ev-' + i, ts: ts(i), channel: 'c', poster_id: 'U-GIGATRON', text: 'event ' + i, ...extra }, { now: new Date(ts(i)) });
}

// genesis key k0 (+ optional recovery key), events 1..n signed by k0.
function start(n = 2, opts = {}) {
  const k0 = testKey();
  const rec = opts.recovery ? testKey() : null;
  let feed = emptyFeed('rot-feed', k0.publicKey, new Date(T0), { recoveryPubkey: rec ? rec.publicKey : '' });
  for (let i = 1; i <= n; i++) feed = add(feed, k0.priv, i);
  return { k0, rec, feed, pin: anchorFingerprint(feed.genesis) };
}

test('valid rotation: anchor follows the chain, new key signs, old key accepted inside grace', () => {
  const { k0, feed: f0, pin } = start(2);
  const k1 = testKey();
  let feed = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(3), graceEvents: 2 }, { now: new Date(ts(3)) });
  assert.equal(feed.key_id, keyId(k1.publicKey));
  assert.equal(feed.key_log.length, 1);
  feed = add(feed, k0.priv, 4); // old key, inside grace (seq 4 <= 3 + 2)
  feed = add(feed, k1.priv, 5);
  feed = add(feed, k1.priv, 6);
  const { bytes, sig } = signed(k1, feed);
  const v = verifyFeedDetailed(bytes, sig, pin); // same pin as before rotation
  assert.equal(v.keyId, keyId(k1.publicKey));
  assert.deepEqual(v.rotations.map((r) => [r.seq, r.mode, r.from, r.to]), [[3, 'normal', keyId(k0.publicKey), keyId(k1.publicKey)]]);
  // The genesis key pin (v0.1 style) also follows the chain.
  assert.equal(verifyFeed(bytes, sig, k0.publicKey).head.seq, 6);
  // NDJSON encoding of the same history verifies too.
  const nd = serializeFeedNdjson(feed);
  assert.equal(verifyFeed(nd, signFeedBytes(k1.priv, Buffer.from(nd)), pin).head.seq, 6);
});

test('valid rotation: consumer with pre-rotation state moves to the new key and reports it', () => {
  const { k0, feed: f0, pin } = start(2);
  const s0 = signed(k0, f0);
  const r0 = applyFeed(emptyState(), verifyFeed(s0.bytes, s0.sig, pin), POLICY);
  const k1 = testKey();
  let feed = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(3), poster_id: 'publisher' }, { now: new Date(ts(3)) });
  feed = add(feed, k1.priv, 4);
  const s1 = signed(k1, feed);
  const r1 = applyFeed(r0.state, verifyFeed(s1.bytes, s1.sig, pin), POLICY);
  assert.deepEqual(r1.accepted.map((e) => e.id), ['rot-1', 'ev-4']);
  assert.equal(r1.keyChanges.length, 1);
  assert.ok(r1.warnings.some((w) => /rotated at seq 3/.test(w)));
  assert.equal(r1.state.key_id, keyId(k1.publicKey));
  assert.equal(r1.state.key_log_len, 1);
});

test('valid rotation: first pull of a window pruned past the rotation still verifies via key_log', () => {
  const { k0, feed: f0, pin } = start(2);
  const k1 = testKey();
  let feed = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(3) }, { now: new Date(ts(3)) });
  for (let i = 4; i <= 8; i++) feed = appendEvent(feed, k1.priv, { type: 'task', id: 'ev-' + i, ts: ts(i), channel: 'c', poster_id: 'U-GIGATRON', text: 'e' }, { now: new Date(ts(i)), keep: 3 });
  assert.equal(feed.events[0].seq, 6);
  const { bytes, sig } = signed(k1, feed);
  assert.equal(verifyFeed(bytes, sig, pin).head.seq, 8);
});

test('detached file signature must come from the CURRENT key after rotation', () => {
  const { k0, feed: f0, pin } = start(1);
  const k1 = testKey();
  const feed = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(2), graceEvents: 5 }, { now: new Date(ts(2)) });
  const { bytes, sig } = signed(k0, feed);
  assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_BAD_SIGNATURE');
});

test('bad-signature rotation: not signed by the current key', () => {
  const { feed: f0, pin, k0 } = start(2);
  const stranger = testKey();
  const k1 = testKey();
  const rot = { mode: 'normal', prev_key_id: keyId(k0.publicKey), next_pubkey: k1.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: '', next_recovery_digest: '' };
  const feed = forgeEvent(f0, stranger.priv, { type: 'rotate', id: 'rot-x', ts: ts(3), rotate: rot }, k1.priv);
  const { bytes, sig } = signed(k1, feed);
  assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_BAD_ROTATION');
  assert.throws(() => rotateKey(f0, stranger.priv, k1.priv, { id: 'rot-y', ts: ts(3) }), /not the current key/);
});

test('bad-signature rotation: missing/wrong countersignature by the next key', () => {
  const { feed: f0, pin, k0 } = start(2);
  const k1 = testKey();
  const other = testKey();
  const rot = { mode: 'normal', prev_key_id: keyId(k0.publicKey), next_pubkey: k1.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: '', next_recovery_digest: '' };
  const feed = forgeEvent(f0, k0.priv, { type: 'rotate', id: 'rot-x', ts: ts(3), rotate: rot }, other.priv);
  const { bytes, sig } = signed(k1, feed);
  assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_BAD_ROTATION');
});

test('bad rotation: edited rotate body (hash mismatch) and wrong prev_key_id are rejected', () => {
  const { k0, feed: f0, pin } = start(2);
  const k1 = testKey();
  const feed = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(3) }, { now: new Date(ts(3)) });
  const evil = structuredClone(feed);
  evil.key_log[0].rotate.grace_events = 9999;
  evil.events[2].rotate.grace_events = 9999;
  const a = signed(k1, evil);
  assert.equal(codeOf(() => verifyFeed(a.bytes, a.sig, pin)), 'HIVE_TAMPERED');
  const rot = { mode: 'normal', prev_key_id: '0123456789abcdef', next_pubkey: k1.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: '', next_recovery_digest: '' };
  const forged = forgeEvent(f0, k0.priv, { type: 'rotate', id: 'rot-x', ts: ts(3), rotate: rot }, k1.priv);
  const b = signed(k1, forged);
  assert.equal(codeOf(() => verifyFeed(b.bytes, b.sig, pin)), 'HIVE_BAD_ROTATION');
});

test('bad rotation: old key cannot rotate during its own grace window', () => {
  const { k0, feed: f0, pin } = start(1);
  const k1 = testKey();
  const k2 = testKey();
  const feed1 = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(2), graceEvents: 5 }, { now: new Date(ts(2)) });
  const rot = { mode: 'normal', prev_key_id: keyId(k1.publicKey), next_pubkey: k2.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: '', next_recovery_digest: '' };
  const forged = forgeEvent(feed1, k0.priv, { type: 'rotate', id: 'rot-2', ts: ts(3), rotate: rot }, k2.priv);
  const { bytes, sig } = signed(k2, forged);
  assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_BAD_ROTATION');
});

test('bad rotation: a rotate event in the window that is not in key_log is rejected', () => {
  const { k0, feed: f0, pin } = start(2);
  const k1 = testKey();
  const feed = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(3) }, { now: new Date(ts(3)) });
  const evil = { ...feed, key_log: [], key_id: keyId(k0.publicKey) };
  const { bytes, sig } = signed(k0, evil);
  assert.equal(codeOf(() => verifyFeed(bytes, sig, pin)), 'HIVE_BAD_ROTATION');
});

test('rotation replay: duplicated key_log entry, rotating back to an old key, re-used old rotation', () => {
  const { k0, feed: f0, pin } = start(1);
  const k1 = testKey();
  const feed1 = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(2) }, { now: new Date(ts(2)) });
  // (a) same rotation listed twice
  const dup = { ...feed1, key_log: [feed1.key_log[0], feed1.key_log[0]] };
  const a = signed(k1, dup);
  assert.equal(codeOf(() => verifyFeed(a.bytes, a.sig, pin)), 'HIVE_ROTATION_REPLAY');
  // (b) properly signed rotation k1 -> k0 (back to a used key)
  const back = { mode: 'normal', prev_key_id: keyId(k1.publicKey), next_pubkey: k0.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: '', next_recovery_digest: '' };
  const fb = forgeEvent(feed1, k1.priv, { type: 'rotate', id: 'rot-back', ts: ts(3), rotate: back }, k0.priv);
  const b = signed(k0, fb);
  assert.equal(codeOf(() => verifyFeed(b.bytes, b.sig, pin)), 'HIVE_ROTATION_REPLAY');
  assert.throws(() => rotateKey(feed1, k1.priv, k0.priv, { id: 'rot-back', ts: ts(3) }), { code: 'HIVE_ROTATION_REPLAY' });
  // (c) the old k0->k1 rotation replayed at a later seq (same id, re-hashed):
  // caught as a replay; its signature also covers the old seq/prev_hash and
  // its prev_key_id no longer names the current key.
  const old = feed1.key_log[0];
  const replay = { ...feed1, events: [...feed1.events, { ...old, seq: 3, prev_hash: feed1.head.hash }] };
  replay.events[2].hash = eventHash(replay.events[2]);
  replay.key_log = [old, replay.events[2]];
  replay.head = { seq: 3, hash: replay.events[2].hash };
  const c = signed(k1, replay);
  assert.equal(codeOf(() => verifyFeed(c.bytes, c.sig, pin)), 'HIVE_ROTATION_REPLAY');
  // Same replay with a fresh id still fails (bad signature / wrong prev_key_id).
  const replay2 = structuredClone(replay);
  replay2.events[2].id = 'rot-1-again';
  replay2.events[2].hash = eventHash(replay2.events[2]);
  replay2.key_log = [old, replay2.events[2]];
  replay2.head = { seq: 3, hash: replay2.events[2].hash };
  const d = signed(k1, replay2);
  assert.equal(codeOf(() => verifyFeed(d.bytes, d.sig, pin)), 'HIVE_BAD_ROTATION');
});

test('consumer detects a rewritten key history (key equivocation) even if it verifies', () => {
  const { k0, feed: f0, pin } = start(1);
  const k1 = testKey();
  const k1b = testKey();
  const a = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(2), poster_id: 'publisher' }, { now: new Date(ts(2)) });
  const b = rotateKey(f0, k0.priv, k1b.priv, { id: 'rot-1', ts: ts(2), poster_id: 'publisher' }, { now: new Date(ts(2)) });
  const b2 = add(b, k1b.priv, 3);
  const sa = signed(k1, a);
  const sb = signed(k1b, b2);
  const r = applyFeed(emptyState(), verifyFeed(sa.bytes, sa.sig, pin), POLICY);
  assert.equal(codeOf(() => applyFeed(r.state, verifyFeed(sb.bytes, sb.sig, pin), POLICY)), 'HIVE_KEY_CHANGED');
});

test('events signed by the old key after the grace window (count) are rejected', () => {
  const { k0, feed: f0, pin } = start(1);
  const k1 = testKey();
  let feed = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(2), graceEvents: 2 }, { now: new Date(ts(2)) });
  feed = add(feed, k0.priv, 3);
  feed = add(feed, k0.priv, 4); // last grace event (seq 4 = 2 + 2)
  const ok = signed(k1, feed);
  assert.equal(verifyFeed(ok.bytes, ok.sig, pin).head.seq, 4);
  assert.throws(() => add(feed, k0.priv, 5), /grace window over/);
  const late = forgeEvent(feed, k0.priv, { id: 'late-5', ts: ts(5) });
  const s = signed(k1, late);
  assert.equal(codeOf(() => verifyFeed(s.bytes, s.sig, pin)), 'HIVE_KEY_RETIRED');
});

test('events signed by the old key after grace_until (time) are rejected; grace 0 means none', () => {
  const { k0, feed: f0, pin } = start(1);
  const k1 = testKey();
  const feed = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(2), graceEvents: 10, graceUntil: ts(3) }, { now: new Date(ts(2)) });
  const inTime = forgeEvent(feed, k0.priv, { id: 'e3', ts: ts(3) });
  const s1 = signed(k1, inTime);
  assert.equal(verifyFeed(s1.bytes, s1.sig, pin).head.seq, 3);
  const tooLate = forgeEvent(inTime, k0.priv, { id: 'e4', ts: ts(4) });
  const s2 = signed(k1, tooLate);
  assert.equal(codeOf(() => verifyFeed(s2.bytes, s2.sig, pin)), 'HIVE_KEY_RETIRED');
  const noGrace = rotateKey(f0, k0.priv, k1.priv, { id: 'rot-1', ts: ts(2) }, { now: new Date(ts(2)) });
  const s3 = signed(k1, forgeEvent(noGrace, k0.priv, { id: 'e3', ts: ts(3) }));
  assert.equal(codeOf(() => verifyFeed(s3.bytes, s3.sig, pin)), 'HIVE_KEY_RETIRED');
});

test('recovery-key rotation: pre-committed offline key force-rotates away from a stolen key', () => {
  const { k0, rec, feed: f0, pin } = start(2, { recovery: true });
  assert.equal(f0.genesis.recovery_digest, publicKeyDigest(rec.publicKey));
  const k2 = testKey();
  const rec2 = testKey();
  let feed = recoverKey(f0, rec.priv, k2.priv, { id: 'recover-1', ts: ts(3), poster_id: 'publisher', nextRecoveryPubkey: rec2.publicKey }, { now: new Date(ts(3)) });
  feed = add(feed, k2.priv, 4);
  const s = signed(k2, feed);
  const v = verifyFeedDetailed(s.bytes, s.sig, pin);
  assert.deepEqual(v.rotations.map((r) => r.mode), ['recovery']);
  assert.equal(feed.key_log[0].rotate.next_recovery_digest, publicKeyDigest(rec2.publicKey));
  // The thief's k0 is rejected immediately (no grace on recovery).
  const thief = signed(k2, forgeEvent(feed, k0.priv, { id: 'thief', ts: ts(5) }));
  assert.equal(codeOf(() => verifyFeed(thief.bytes, thief.sig, pin)), 'HIVE_KEY_RETIRED');
  // The thief cannot rotate either: k0 is no longer current.
  assert.throws(() => rotateKey(feed, k0.priv, testKey().priv, { id: 'thief-rot', ts: ts(5) }), /not the current key/);
  // The used recovery key is consumed; the freshly committed one works.
  assert.throws(() => recoverKey(feed, rec.priv, testKey().priv, { id: 'again', ts: ts(5) }), { code: 'HIVE_BAD_ROTATION' });
  const k3 = testKey();
  const f2 = recoverKey(feed, rec2.priv, k3.priv, { id: 'recover-2', ts: ts(5) }, { now: new Date(ts(5)) });
  const s2 = signed(k3, f2);
  assert.equal(verifyFeed(s2.bytes, s2.sig, pin).key_id, keyId(k3.publicKey));
});

test('recovery also works after a thief has already rotated the key', () => {
  const { k0, rec, feed: f0, pin } = start(1, { recovery: true });
  const thiefKey = testKey();
  const stolen = rotateKey(f0, k0.priv, thiefKey.priv, { id: 'thief-rot', ts: ts(2) }, { now: new Date(ts(2)) });
  const k2 = testKey();
  const recovered = recoverKey(stolen, rec.priv, k2.priv, { id: 'recover-1', ts: ts(3) }, { now: new Date(ts(3)) });
  const s = signed(k2, recovered);
  assert.equal(verifyFeed(s.bytes, s.sig, pin).key_id, keyId(k2.publicKey));
});

test('recovery with the wrong key is rejected', () => {
  const { k0, feed: f0, pin } = start(2, { recovery: true });
  const wrong = testKey();
  const k2 = testKey();
  assert.throws(() => recoverKey(f0, wrong.priv, k2.priv, { id: 'recover-x', ts: ts(3) }), { code: 'HIVE_BAD_ROTATION' });
  // Hand-forged recovery event with the wrong key revealed and used to sign.
  const rot = { mode: 'recovery', prev_key_id: keyId(k0.publicKey), next_pubkey: k2.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: wrong.publicKey, next_recovery_digest: '' };
  const forged = forgeEvent(f0, wrong.priv, { type: 'rotate', id: 'recover-x', ts: ts(3), rotate: rot }, k2.priv);
  const s = signed(k2, forged);
  assert.equal(codeOf(() => verifyFeed(s.bytes, s.sig, pin)), 'HIVE_BAD_ROTATION');
});

test('recovery naming the committed key but signed by another key is rejected', () => {
  const { k0, rec, feed: f0, pin } = start(1, { recovery: true });
  const impostor = testKey();
  const k2 = testKey();
  const rot = { mode: 'recovery', prev_key_id: keyId(k0.publicKey), next_pubkey: k2.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: rec.publicKey, next_recovery_digest: '' };
  const s = signed(k2, forgeEvent(f0, impostor.priv, { type: 'rotate', id: 'rec', ts: ts(2), rotate: rot }, k2.priv));
  assert.equal(codeOf(() => verifyFeed(s.bytes, s.sig, pin)), 'HIVE_BAD_ROTATION');
  // The stolen CURRENT key cannot sign a recovery rotation either.
  const s2 = signed(k2, forgeEvent(f0, k0.priv, { type: 'rotate', id: 'rec', ts: ts(2), rotate: rot }, k2.priv));
  assert.equal(codeOf(() => verifyFeed(s2.bytes, s2.sig, pin)), 'HIVE_BAD_ROTATION');
});

test('recovery is refused when no recovery key was committed in genesis', () => {
  const { k0, feed: f0, pin } = start(1);
  const r = testKey();
  const k2 = testKey();
  assert.throws(() => recoverKey(f0, r.priv, k2.priv, { id: 'rec', ts: ts(2) }), /no recovery key is committed/);
  const rot = { mode: 'recovery', prev_key_id: keyId(k0.publicKey), next_pubkey: k2.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: r.publicKey, next_recovery_digest: '' };
  const s = signed(k2, forgeEvent(f0, r.priv, { type: 'rotate', id: 'rec', ts: ts(2), rotate: rot }, k2.priv));
  assert.equal(codeOf(() => verifyFeed(s.bytes, s.sig, pin)), 'HIVE_BAD_ROTATION');
});

test('a normal rotation (current key only) cannot change or use the recovery key', () => {
  const { k0, rec, feed: f0, pin } = start(1, { recovery: true });
  const k1 = testKey();
  const evilRec = testKey();
  const rot = { mode: 'normal', prev_key_id: keyId(k0.publicKey), next_pubkey: k1.publicKey, grace_events: 0, grace_until: '', recovery_pubkey: '', next_recovery_digest: publicKeyDigest(evilRec.publicKey) };
  const s = signed(k1, forgeEvent(f0, k0.priv, { type: 'rotate', id: 'r', ts: ts(2), rotate: rot }, k1.priv));
  assert.match(codeOf(() => verifyFeed(s.bytes, s.sig, pin)), /HIVE_BAD_ROTATION|HIVE_INVALID_FEED/);
  // Nor rotate TO the recovery key (which would put the offline key online).
  assert.throws(() => rotateKey(f0, k0.priv, rec.priv, { id: 'r', ts: ts(2) }), /recovery key/);
});
