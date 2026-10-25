// Consumer-side policy: given a feed that already passed verifyFeed(), decide
// which events are new and trustworthy relative to locally persisted state.
// Event text is untrusted DATA. Nothing here interprets or executes it.
import { anchorFingerprint } from './anchor.js';

export const DEFAULT_POLICY = Object.freeze({
  maxAgeSec: 24 * 3600,
  maxSkewSec: 300,
  maxFeedAgeSec: 7 * 24 * 3600,
  strictFreshness: false,
  seenIdLimit: 5000
});

export function emptyState() {
  return {
    feed_id: null, anchor: null, key_id: null, key_log_len: 0, key_log_head: null,
    seq: 0, hash: '0'.repeat(64), seen_ids: [], etag: null
  };
}

function fail(msg, code) {
  const err = new Error(msg);
  err.code = code;
  throw err;
}

export function applyFeed(state, feed, opts = {}) {
  const policy = { ...DEFAULT_POLICY, ...opts };
  const now = (opts.now || new Date()).getTime();
  const trusted = new Set(opts.trustedPosters || []);
  const st = { ...emptyState(), ...state };
  const warnings = [];

  if (st.feed_id && st.feed_id !== feed.feed_id) fail('state is for feed ' + st.feed_id + ', got ' + feed.feed_id, 'HIVE_WRONG_FEED');
  const anchor = anchorFingerprint(feed.genesis);
  if (st.anchor && st.anchor !== anchor) fail('feed anchor (genesis) changed; this is a different feed. Re-pin deliberately.', 'HIVE_ANCHOR_CHANGED');
  if (!st.anchor && st.key_id && st.key_id !== feed.key_id) fail('feed key changed and state has no anchor (v0.1 state); re-pin deliberately', 'HIVE_KEY_CHANGED');
  // The key history is append-only: the rotations we already accepted must
  // still be there, unchanged, as a prefix of key_log.
  const kl = feed.key_log;
  if (st.key_log_len > kl.length) fail('key history shrank: had ' + st.key_log_len + ' rotations, feed has ' + kl.length, 'HIVE_KEY_CHANGED');
  if (st.key_log_len > 0 && kl[st.key_log_len - 1].hash !== st.key_log_head) fail('key history rewritten (rotation ' + st.key_log_len + ' differs from the one we accepted)', 'HIVE_KEY_CHANGED');
  if (feed.head.seq < st.seq) fail('rollback: feed head ' + feed.head.seq + ' < last seen ' + st.seq, 'HIVE_ROLLBACK');
  if (feed.head.seq === st.seq && feed.head.hash !== st.hash) fail('fork: same seq, different head hash', 'HIVE_FORK');

  const first = feed.events[0];
  if (st.seq > 0) {
    const atSeen = feed.events.find((e) => e.seq === st.seq);
    if (atSeen) {
      if (atSeen.hash !== st.hash) fail('fork: event ' + st.seq + ' hash differs from last seen', 'HIVE_FORK');
    } else if (first && first.seq === st.seq + 1) {
      if (first.prev_hash !== st.hash) fail('fork: event ' + first.seq + ' does not link to last seen', 'HIVE_FORK');
    } else if (feed.head.seq > st.seq) {
      warnings.push('gap: events ' + (st.seq + 1) + '..' + ((first ? first.seq : feed.head.seq + 1) - 1) + ' were pruned before we saw them; linkage to our state cannot be checked');
    }
  } else if (first && first.seq > 1) {
    warnings.push('first pull starts mid-chain at seq ' + first.seq + '; earlier history not verified');
  }

  const keyChanges = kl.slice(st.key_log_len).map((r) => ({ seq: r.seq, mode: r.rotate.mode, from: r.rotate.prev_key_id, next_pubkey: r.rotate.next_pubkey }));
  for (const k of keyChanges) {
    warnings.push('publisher key ' + (k.mode === 'recovery' ? 'FORCE-ROTATED by recovery key' : 'rotated') + ' at seq ' + k.seq + ' (from ' + k.from + ')');
  }

  const feedAge = (now - Date.parse(feed.updated)) / 1000;
  if (feedAge > policy.maxFeedAgeSec) {
    const msg = 'stale feed: updated ' + Math.round(feedAge) + 's ago (possible freeze attack or idle publisher)';
    if (policy.strictFreshness) fail(msg, 'HIVE_STALE');
    warnings.push(msg);
  }

  const seen = new Set(st.seen_ids);
  const accepted = [];
  const skipped = [];
  for (const ev of feed.events) {
    if (ev.seq <= st.seq) continue;
    const t = Date.parse(ev.ts);
    let reason = null;
    if (seen.has(ev.id)) reason = 'replay: id already seen';
    else if (t > now + policy.maxSkewSec * 1000) reason = 'ts in the future';
    else if (t < now - policy.maxAgeSec * 1000) reason = 'too old';
    else if (!trusted.has(ev.poster_id)) reason = 'poster_id not in verified list';
    seen.add(ev.id);
    if (reason) skipped.push({ seq: ev.seq, id: ev.id, reason });
    else accepted.push(ev);
  }

  const seenIds = [...seen].slice(-policy.seenIdLimit);
  const newState = {
    ...st,
    feed_id: feed.feed_id,
    anchor,
    key_id: feed.key_id,
    key_log_len: kl.length,
    key_log_head: kl.length ? kl[kl.length - 1].hash : null,
    seq: feed.head.seq,
    hash: feed.head.hash,
    seen_ids: seenIds
  };
  return { accepted, skipped, warnings, keyChanges, state: newState };
}
