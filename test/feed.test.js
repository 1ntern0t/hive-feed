import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  verifyFeed, parseFeed, serializeFeed, serializeFeedNdjson, signFeedBytes, canonicalize, eventHash,
  eventSigningBytes, signBytes, appendEvent, emptyFeed, GENESIS_HASH
} from '../src/index.js';
import { testKey, buildFeed, signed, resignRaw, NOW } from './helpers.js';

const key = testKey();

function codeOf(fn) {
  try {
    fn();
  } catch (e) {
    return e.code || e.message;
  }
  return 'NO_ERROR';
}

test('valid feed verifies (JSON)', () => {
  const feed = buildFeed(key, 5);
  const { bytes, sig } = signed(key, feed);
  const out = verifyFeed(bytes, sig, key.publicKey);
  assert.equal(out.head.seq, 5);
  assert.equal(out.events[0].prev_hash, GENESIS_HASH);
  assert.equal(out.events[4].hash, out.head.hash);
});

test('valid feed verifies (NDJSON)', () => {
  const feed = buildFeed(key, 3);
  const nd = serializeFeedNdjson(feed);
  const sig = signFeedBytes(key.priv, Buffer.from(nd));
  assert.equal(verifyFeed(nd, sig, key.publicKey).head.seq, 3);
});

test('empty feed verifies in both encodings', () => {
  const feed = emptyFeed('empty', key.publicKey, NOW);
  const j = signed(key, feed);
  assert.equal(verifyFeed(j.bytes, j.sig, key.publicKey).events.length, 0);
  const nd = serializeFeedNdjson(feed);
  assert.equal(verifyFeed(nd, signFeedBytes(key.priv, Buffer.from(nd)), key.publicKey).events.length, 0);
});

test('canonicalize sorts keys and rejects floats/null', () => {
  assert.equal(canonicalize({ b: 1, a: 'x' }), '{"a":"x","b":1}');
  assert.throws(() => canonicalize({ a: 1.5 }));
  assert.throws(() => canonicalize({ a: null }));
});

test('bad signature: wrong key rejected', () => {
  const other = testKey();
  const { bytes } = signed(key, buildFeed(key, 2));
  const sigOther = signFeedBytes(other.priv, bytes);
  assert.equal(codeOf(() => verifyFeed(bytes, sigOther, key.publicKey)), 'HIVE_BAD_SIGNATURE');
});

test('bad signature: garbage / truncated signature rejected', () => {
  const { bytes, sig } = signed(key, buildFeed(key, 2));
  assert.equal(codeOf(() => verifyFeed(bytes, 'AAAA', key.publicKey)), 'HIVE_BAD_SIGNATURE');
  assert.equal(codeOf(() => verifyFeed(bytes, sig.slice(0, 40), key.publicKey)), 'HIVE_BAD_SIGNATURE');
  const flipped = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
  assert.equal(codeOf(() => verifyFeed(bytes, flipped, key.publicKey)), 'HIVE_BAD_SIGNATURE');
});

test('feed signed by the right key but pinned to a different key is rejected', () => {
  const other = testKey();
  const feed = buildFeed(other, 1);
  const { bytes, sig } = signed(other, feed);
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey)), 'HIVE_ANCHOR_MISMATCH');
});

test('tampering: any byte change breaks the detached signature', () => {
  const { bytes, sig } = signed(key, buildFeed(key, 3));
  const s = bytes.toString();
  for (const t of [s.replace('event number 2', 'event number X'), s.replace('U-GIGATRON', 'U-GIGATRAN'), s.replace('"task"', '"result"')]) {
    assert.notEqual(t, s);
    assert.equal(codeOf(() => verifyFeed(t, sig, key.publicKey)), 'HIVE_BAD_SIGNATURE');
  }
});

test('tampering: event edited and file re-signed still fails event hash/sig', () => {
  const feed = buildFeed(key, 3);
  const evil = structuredClone(feed);
  evil.events[1].poster_id = 'U-ATTACKER';
  const { bytes, sig } = resignRaw(key, serializeFeed(evil));
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey)), 'HIVE_TAMPERED');
});

test('tampering: text changed without digest -> rejected', () => {
  const feed = buildFeed(key, 2);
  const evil = structuredClone(feed);
  evil.events[0].text = 'rm -rf /';
  const { bytes, sig } = resignRaw(key, serializeFeed(evil));
  assert.match(codeOf(() => verifyFeed(bytes, sig, key.publicKey)), /HIVE_INVALID_FEED/);
});

test('event signature from another key is rejected even with valid hash', () => {
  const other = testKey();
  const feed = buildFeed(key, 2);
  const evil = structuredClone(feed);
  evil.events[1].sig = signBytes(other.priv, eventSigningBytes(evil.events[1]));
  const { bytes, sig } = resignRaw(key, serializeFeed(evil));
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey)), 'HIVE_BAD_SIGNATURE');
});

test('reordering events breaks the chain', () => {
  const feed = buildFeed(key, 4);
  const evil = structuredClone(feed);
  [evil.events[1], evil.events[2]] = [evil.events[2], evil.events[1]];
  const { bytes, sig } = resignRaw(key, serializeFeed(evil));
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey)), 'HIVE_BROKEN_CHAIN');
});

test('truncated chain: middle event removed -> broken chain', () => {
  const feed = buildFeed(key, 4);
  const evil = structuredClone(feed);
  evil.events.splice(1, 1);
  const { bytes, sig } = resignRaw(key, serializeFeed(evil));
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey)), 'HIVE_BROKEN_CHAIN');
});

test('truncated chain: last event dropped but head kept -> head mismatch', () => {
  const feed = buildFeed(key, 3);
  const evil = structuredClone(feed);
  evil.events.pop();
  const { bytes, sig } = resignRaw(key, serializeFeed(evil));
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey)), 'HIVE_BROKEN_CHAIN');
});

test('truncated file bytes are rejected', () => {
  const { bytes, sig } = signed(key, buildFeed(key, 3));
  const cut = bytes.subarray(0, bytes.length - 40);
  // v0.2 parses (size-limited, canonical) before the signature check, because
  // the signing key comes from the pinned genesis + key history in the file.
  assert.equal(codeOf(() => verifyFeed(cut, sig, key.publicKey)), 'HIVE_INVALID_FEED');
  // Even if re-signed, the cut JSON does not parse.
  const re = signFeedBytes(key.priv, cut);
  assert.equal(codeOf(() => verifyFeed(cut, re, key.publicKey)), 'HIVE_INVALID_FEED');
});

test('pruned window (keep) verifies and starts mid-chain', () => {
  const feed = buildFeed(key, 6, { keep: 3 });
  assert.equal(feed.events.length, 3);
  assert.equal(feed.events[0].seq, 4);
  const { bytes, sig } = signed(key, feed);
  assert.equal(verifyFeed(bytes, sig, key.publicKey).head.seq, 6);
});

test('replay inside a feed: duplicate id rejected', () => {
  const feed = buildFeed(key, 2);
  // Craft a third event that reuses id ev-1 but is otherwise valid.
  const evil = structuredClone(feed);
  const ev = { ...evil.events[0], seq: 3, prev_hash: evil.head.hash, ts: evil.events[1].ts };
  ev.hash = eventHash(ev);
  ev.sig = signBytes(key.priv, eventSigningBytes(ev));
  evil.events.push(ev);
  evil.head = { seq: 3, hash: ev.hash };
  const { bytes, sig } = resignRaw(key, serializeFeed(evil));
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey)), 'HIVE_REPLAY');
});

test('appendEvent refuses duplicate id and backwards ts', () => {
  const feed = buildFeed(key, 2);
  assert.throws(() => appendEvent(feed, key.priv, { type: 'task', id: 'ev-1', channel: 'c', poster_id: 'p', text: 'x' }, { now: NOW }));
  assert.throws(() => appendEvent(feed, key.priv, { type: 'task', id: 'new', ts: '2000-01-01T00:00:00Z', channel: 'c', poster_id: 'p', text: 'x' }, { now: NOW }));
});

test('appendEvent refuses a key that does not match the feed', () => {
  const other = testKey();
  const feed = buildFeed(key, 1);
  assert.throws(() => appendEvent(feed, other.priv, { type: 'task', id: 'z', channel: 'c', poster_id: 'p', text: 'x' }), /does not match/);
});

test('oversized input rejected before parsing', () => {
  const big = Buffer.alloc(2 * 1024 * 1024, 0x20);
  assert.equal(codeOf(() => verifyFeed(big, 'x', key.publicKey)), 'HIVE_TOO_LARGE');
  assert.equal(codeOf(() => parseFeed(big)), 'HIVE_TOO_LARGE');
  const { bytes, sig } = signed(key, buildFeed(key, 5));
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey, { maxBytes: 100 })), 'HIVE_TOO_LARGE');
  assert.equal(codeOf(() => verifyFeed(bytes, sig, key.publicKey, { maxEvents: 2 })), 'HIVE_TOO_LARGE');
});

test('oversized text rejected at append', () => {
  const feed = emptyFeed('f', key.publicKey, NOW);
  assert.throws(() => appendEvent(feed, key.priv, { type: 'task', id: 'a', channel: 'c', poster_id: 'p', text: 'x'.repeat(4001) }, { now: NOW }), /text/);
});

test('non-canonical bytes (whitespace, duplicate keys) rejected even if signed', () => {
  const feed = buildFeed(key, 1);
  const pretty = JSON.stringify(feed, null, 2);
  const a = resignRaw(key, pretty);
  assert.equal(codeOf(() => verifyFeed(a.bytes, a.sig, key.publicKey)), 'HIVE_INVALID_FEED');
  const dup = serializeFeed(feed).replace('{"events"', '{"feed_id":"other","events"');
  const b = resignRaw(key, dup);
  assert.equal(codeOf(() => verifyFeed(b.bytes, b.sig, key.publicKey)), 'HIVE_INVALID_FEED');
});

test('unknown fields and bad types rejected', () => {
  const feed = buildFeed(key, 1);
  for (const mut of [
    (f) => { f.extra = 'x'; },
    (f) => { f.events[0].exec = 'x'; },
    (f) => { f.events[0].type = 'shell'; },
    (f) => { f.events[0].url = 'javascript:alert(1)'; },
    (f) => { f.events[0].url = 'http://insecure.example'; },
    (f) => { f.events[0].seq = 1.5; },
    (f) => { f.format = 'hive-feed/0'; }
  ]) {
    const evil = structuredClone(feed);
    mut(evil);
    let str;
    try {
      str = serializeFeed(evil);
    } catch {
      continue; // not even canonicalizable: fine
    }
    const r = resignRaw(key, str);
    assert.notEqual(codeOf(() => verifyFeed(r.bytes, r.sig, key.publicKey)), 'NO_ERROR');
  }
});

test('invalid UTF-8 rejected', () => {
  const bad = Buffer.from([0x7b, 0xff, 0xfe, 0x7d]);
  const r = { bytes: bad, sig: signFeedBytes(key.priv, bad) };
  assert.equal(codeOf(() => verifyFeed(r.bytes, r.sig, key.publicKey)), 'HIVE_INVALID_FEED');
});
