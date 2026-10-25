import { test } from 'node:test';
import assert from 'node:assert/strict';
import { applyFeed, emptyState, appendEvent, verifyFeed } from '../src/index.js';
import { testKey, buildFeed, signed, NOW } from './helpers.js';

const key = testKey();
const POLICY = { trustedPosters: ['U-GIGATRON'], now: NOW };

function code(fn) {
  try {
    fn();
  } catch (e) {
    return e.code;
  }
  return 'NO_ERROR';
}

test('first pull accepts all fresh events from trusted posters', () => {
  const r = applyFeed(emptyState(), buildFeed(key, 3), POLICY);
  assert.equal(r.accepted.length, 3);
  assert.equal(r.state.seq, 3);
});

test('second pull with same feed accepts nothing (replay of whole feed)', () => {
  const feed = buildFeed(key, 3);
  const r1 = applyFeed(emptyState(), feed, POLICY);
  const r2 = applyFeed(r1.state, feed, POLICY);
  assert.equal(r2.accepted.length, 0);
});

test('only new events are returned after append', () => {
  const feed = buildFeed(key, 2);
  const r1 = applyFeed(emptyState(), feed, POLICY);
  const feed2 = appendEvent(feed, key.priv, { type: 'speed_ping', id: 'ping-1', ts: NOW.toISOString(), channel: 'c', poster_id: 'U-GIGATRON', text: 'go' }, { now: NOW });
  const r2 = applyFeed(r1.state, feed2, POLICY);
  assert.deepEqual(r2.accepted.map((e) => e.id), ['ping-1']);
});

test('rollback to an older (validly signed) feed is rejected', () => {
  const old = buildFeed(key, 2);
  const newer = appendEvent(old, key.priv, { type: 'task', id: 'x', ts: NOW.toISOString(), channel: 'c', poster_id: 'U-GIGATRON', text: 't' }, { now: NOW });
  const r = applyFeed(emptyState(), newer, POLICY);
  assert.equal(code(() => applyFeed(r.state, old, POLICY)), 'HIVE_ROLLBACK');
});

test('fork: different history with same seq is rejected', () => {
  const a = buildFeed(key, 3, { idPrefix: 'a-' });
  const b = buildFeed(key, 3, { idPrefix: 'b-' });
  const r = applyFeed(emptyState(), a, POLICY);
  assert.equal(code(() => applyFeed(r.state, b, POLICY)), 'HIVE_FORK');
  const r2 = applyFeed(emptyState(), buildFeed(key, 2, { idPrefix: 'a-' }), POLICY);
  const b4 = appendEvent(b, key.priv, { type: 'task', id: 'b-4', ts: NOW.toISOString(), channel: 'c', poster_id: 'U-GIGATRON', text: 't' }, { now: NOW });
  assert.equal(code(() => applyFeed(r2.state, b4, POLICY)), 'HIVE_FORK');
});

test('replay of an old id under a new seq is skipped', () => {
  const feed = buildFeed(key, 2);
  const r1 = applyFeed(emptyState(), feed, POLICY);
  const replayed = appendEvent(feed, key.priv, { type: 'task', id: 'ev-1-again', ts: NOW.toISOString(), channel: 'c', poster_id: 'U-GIGATRON', text: 'x' }, { now: NOW });
  // simulate publisher compromise re-emitting an id the consumer saw earlier but publisher pruned
  replayed.events[replayed.events.length - 1].id = 'ev-1';
  const r2 = applyFeed(r1.state, replayed, POLICY);
  assert.equal(r2.accepted.length, 0);
  assert.match(r2.skipped[0].reason, /replay/);
});

test('old events (max age) are skipped, future events are skipped', () => {
  const feed = buildFeed(key, 2);
  const r = applyFeed(emptyState(), feed, { ...POLICY, maxAgeSec: 90 });
  assert.deepEqual(r.accepted.map((e) => e.id), ['ev-2']);
  assert.match(r.skipped[0].reason, /too old/);
  const past = new Date(NOW.getTime() - 3600 * 1000);
  const r2 = applyFeed(emptyState(), feed, { ...POLICY, now: past });
  assert.equal(r2.accepted.length, 0);
  assert.ok(r2.skipped.every((s) => /future/.test(s.reason)));
});

test('poster_id not on the verified list is never trusted', () => {
  const feed = buildFeed(key, 2, { poster: 'U-RANDOM' });
  const r = applyFeed(emptyState(), feed, POLICY);
  assert.equal(r.accepted.length, 0);
  assert.ok(r.skipped.every((s) => /verified list/.test(s.reason)));
  const r2 = applyFeed(emptyState(), feed, { now: NOW });
  assert.equal(r2.accepted.length, 0, 'empty trust list trusts nobody');
});

test('gap warning when the window was pruned past our state', () => {
  const r1 = applyFeed(emptyState(), buildFeed(key, 2), POLICY);
  const pruned = buildFeed(key, 8, { keep: 3 });
  const r2 = applyFeed(r1.state, pruned, POLICY);
  assert.ok(r2.warnings.some((w) => /gap/.test(w)));
});

test('stale feed warns, or fails in strict mode', () => {
  const feed = buildFeed(key, 1);
  const later = new Date(NOW.getTime() + 10 * 24 * 3600 * 1000);
  const r = applyFeed(emptyState(), feed, { ...POLICY, now: later });
  assert.ok(r.warnings.some((w) => /stale/.test(w)));
  assert.equal(code(() => applyFeed(emptyState(), feed, { ...POLICY, now: later, strictFreshness: true })), 'HIVE_STALE');
});

test('key change and feed id change require deliberate re-pin', () => {
  const other = testKey();
  const r = applyFeed(emptyState(), buildFeed(key, 1), POLICY);
  assert.equal(code(() => applyFeed(r.state, buildFeed(other, 2), POLICY)), 'HIVE_KEY_CHANGED');
  assert.equal(code(() => applyFeed(r.state, buildFeed(key, 2, { feedId: 'other' }), POLICY)), 'HIVE_WRONG_FEED');
});

test('end to end: verify then apply', () => {
  const { bytes, sig } = signed(key, buildFeed(key, 2));
  const r = applyFeed(emptyState(), verifyFeed(bytes, sig, key.publicKey), POLICY);
  assert.equal(r.accepted.length, 2);
});
