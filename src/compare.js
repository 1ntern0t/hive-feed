// Peer history comparison (equivocation detection between bots).
//
// A "view summary" is what one bot saw of a feed: the anchor it pinned, the
// head, the key history and the event hashes in its verified window. Bots
// exchange views and compare them. Because every event hash commits to the
// whole history before it (prev_hash chain), equal hashes at seq n mean equal
// histories up to n, and the first seq where two views differ is where the
// publisher (or a key thief) showed them different histories.
//
// View summary (format "hive-feed/view-1", canonical JSON):
//   {
//     format, feed_id, anchor (64 hex),
//     head: { seq, hash },
//     key_log: [rotate event hashes, oldest first]    (key_log is never pruned)
//     window: { from_seq, hashes: [hash at from_seq, ..., hash at head.seq] }
//     observer: "" | label (untrusted), observed_at: ISO-8601 UTC,
//     observer_pubkey: "" | base64 Ed25519, sig: "" | base64,
//     digest: sha256("hive-feed/view-1:" + canonical(all fields except digest, sig))
//   }
// The digest makes a view tamper-evident in transit; the optional observer
// signature binds it to the observer's own key. Neither proves the view is
// TRUE: a peer can lie about what it saw. A fork found from two signed feed
// files (both verified against the same anchor) is cryptographic evidence of
// publisher equivocation; a fork found from a peer's view summary is a claim.
import { canonicalize } from './canonical.js';
import { sha256Hex, GENESIS_HASH, RE_TS_STRICT } from './event.js';
import { anchorFingerprint, normalizePin } from './anchor.js';
import { signBytes, verifyBytes, importPublicKey, publicKeyFromPrivate } from './keys.js';
import { DEFAULT_LIMITS } from './feed.js';

export const VIEW_FORMAT = 'hive-feed/view-1';
export const VIEW_DIGEST_DOMAIN = 'hive-feed/view-1:';
export const VIEW_SIG_DOMAIN = 'hive-feed/view-1:sig:';
const VIEW_FIELDS = ['anchor', 'digest', 'feed_id', 'format', 'head', 'key_log', 'observed_at', 'observer', 'observer_pubkey', 'sig', 'window'];
const RE_HEX64 = /^[0-9a-f]{64}$/;
const RE_FEED_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const RE_B64KEY = /^[A-Za-z0-9+/]{43}=$/;
const RE_B64SIG = /^[A-Za-z0-9+/]{86}==$/;

function fail(msg, code = 'HIVE_BAD_VIEW') {
  const err = new Error(msg);
  err.code = code;
  throw err;
}

function digestOf(v) {
  const { digest, sig, ...rest } = v;
  return sha256Hex(Buffer.from(VIEW_DIGEST_DOMAIN + canonicalize(rest), 'utf8'));
}

// Build a view from a feed that ALREADY passed verifyFeed(). opts:
// { observer, now, maxHashes (keep the newest n window hashes), signingKey }
export function makeView(feed, opts = {}) {
  const maxHashes = opts.maxHashes || DEFAULT_LIMITS.maxEvents;
  let events = feed.events;
  if (events.length > maxHashes) events = events.slice(-maxHashes);
  const v = {
    format: VIEW_FORMAT,
    feed_id: feed.feed_id,
    anchor: anchorFingerprint(feed.genesis),
    head: { seq: feed.head.seq, hash: feed.head.hash },
    key_log: feed.key_log.map((e) => e.hash),
    window: { from_seq: events.length ? events[0].seq : feed.head.seq + 1, hashes: events.map((e) => e.hash) },
    observer: opts.observer || '',
    observed_at: (opts.now || new Date()).toISOString(),
    observer_pubkey: opts.signingKey ? publicKeyFromPrivate(opts.signingKey) : '',
    sig: '',
    digest: ''
  };
  v.digest = digestOf(v);
  if (opts.signingKey) v.sig = signBytes(opts.signingKey, Buffer.from(VIEW_SIG_DOMAIN + v.digest, 'utf8'));
  validateView(v);
  return v;
}

export function serializeView(v) {
  return canonicalize(v) + '\n';
}

export function validateView(v) {
  if (v === null || typeof v !== 'object' || Array.isArray(v)) fail('view: must be an object');
  if (Object.keys(v).sort().join() !== VIEW_FIELDS.join()) fail('view: fields must be exactly ' + VIEW_FIELDS.join(','));
  if (v.format !== VIEW_FORMAT) fail('view: unsupported format');
  if (typeof v.feed_id !== 'string' || !RE_FEED_ID.test(v.feed_id)) fail('view: bad feed_id');
  if (typeof v.anchor !== 'string' || !RE_HEX64.test(v.anchor)) fail('view: anchor must be 64 hex chars');
  const h = v.head;
  if (!h || typeof h !== 'object' || Array.isArray(h) || Object.keys(h).sort().join() !== 'hash,seq') fail('view: bad head');
  if (!Number.isSafeInteger(h.seq) || h.seq < 0 || typeof h.hash !== 'string' || !RE_HEX64.test(h.hash)) fail('view: bad head');
  if (h.seq === 0 && h.hash !== GENESIS_HASH) fail('view: empty feed must have genesis head');
  if (!Array.isArray(v.key_log) || v.key_log.length > DEFAULT_LIMITS.maxRotations || !v.key_log.every((x) => typeof x === 'string' && RE_HEX64.test(x))) fail('view: bad key_log');
  const w = v.window;
  if (!w || typeof w !== 'object' || Array.isArray(w) || Object.keys(w).sort().join() !== 'from_seq,hashes') fail('view: bad window');
  if (!Number.isSafeInteger(w.from_seq) || w.from_seq < 1) fail('view: bad window.from_seq');
  if (!Array.isArray(w.hashes) || w.hashes.length > DEFAULT_LIMITS.maxEvents || !w.hashes.every((x) => typeof x === 'string' && RE_HEX64.test(x))) fail('view: bad window.hashes');
  if (w.hashes.length === 0) {
    if (w.from_seq !== h.seq + 1) fail('view: empty window must have from_seq = head.seq + 1');
  } else {
    if (w.from_seq + w.hashes.length - 1 !== h.seq) fail('view: window must end at head.seq');
    if (w.hashes[w.hashes.length - 1] !== h.hash) fail('view: last window hash must equal head.hash');
  }
  if (typeof v.observer !== 'string' || v.observer.length > 128) fail('view: observer must be a string <= 128 chars');
  if (typeof v.observed_at !== 'string' || !RE_TS_STRICT.test(v.observed_at) || !Number.isFinite(Date.parse(v.observed_at))) fail('view: bad observed_at');
  if (v.observer_pubkey !== '' && (typeof v.observer_pubkey !== 'string' || !RE_B64KEY.test(v.observer_pubkey))) fail('view: bad observer_pubkey');
  if (v.sig !== '' && (typeof v.sig !== 'string' || !RE_B64SIG.test(v.sig))) fail('view: bad sig');
  if ((v.sig === '') !== (v.observer_pubkey === '')) fail('view: sig and observer_pubkey must both be set or both be empty');
}

// Parse and check a view summary. Throws HIVE_BAD_VIEW on shape/digest/sig
// problems. Returns { view, signed }. Canonical bytes are required.
export function parseView(bytes) {
  const str = Buffer.isBuffer(bytes) ? bytes.toString('utf8') : String(bytes);
  if (str.length > 2 * DEFAULT_LIMITS.maxBytes) fail('view: too large', 'HIVE_TOO_LARGE');
  let v;
  try {
    v = JSON.parse(str);
  } catch {
    fail('view: not valid JSON');
  }
  validateView(v);
  if (serializeView(v) !== str && canonicalize(v) !== str) fail('view: bytes are not in canonical form');
  if (digestOf(v) !== v.digest) fail('view: digest does not match contents (edited view)', 'HIVE_TAMPERED');
  if (v.sig !== '' && !verifyBytes(importPublicKey(v.observer_pubkey), Buffer.from(VIEW_SIG_DOMAIN + v.digest, 'utf8'), v.sig)) {
    fail('view: observer signature does not verify', 'HIVE_BAD_SIGNATURE');
  }
  return { view: v, signed: v.sig !== '' };
}

function hashAt(v, seq) {
  if (seq === 0) return GENESIS_HASH;
  const i = seq - v.window.from_seq;
  if (i < 0 || i >= v.window.hashes.length) return null;
  return v.window.hashes[i];
}

function compareKeyLogs(a, b) {
  const n = Math.min(a.length, b.length);
  for (let i = 0; i < n; i++) if (a[i] !== b[i]) return { consistent: false, divergence_index: i };
  return { consistent: true, divergence_index: null };
}

// Compare two views. Returns
// { verdict, behind, divergence_seq, divergence_exact, key_log, detail }
// verdict: 'consistent'        same anchor, same head
//          'prefix'            one view is an earlier state of the other
//                              (behind: 'a' | 'b')
//          'fork'              different histories under the same anchor;
//                              divergence_seq is the earliest seq that differs
//                              (exact, or an upper bound when the windows were
//                              pruned: divergence_exact false)
//          'different_genesis' different anchors: different feeds, not comparable
//          'undetermined'      same anchor but the windows do not overlap
//                              enough to tell
export function compareViews(a, b) {
  validateView(a);
  validateView(b);
  const base = { verdict: null, behind: null, divergence_seq: null, divergence_exact: null, key_log: null, detail: '' };
  if (a.anchor !== b.anchor) return { ...base, verdict: 'different_genesis', detail: 'anchors differ: these are different feeds (or someone pinned the wrong anchor)' };
  if (a.feed_id !== b.feed_id) fail('views share an anchor but not a feed_id (malformed view)');
  const kl = compareKeyLogs(a.key_log, b.key_log);
  base.key_log = kl;
  const sa = a.head.seq;
  const sb = b.head.seq;
  const lo = Math.max(a.window.from_seq, b.window.from_seq, 1);
  const hi = Math.min(sa, sb);

  // Scan the overlapping seq range for the first differing hash.
  let firstDiff = null;
  let lastEqual = null;
  for (let s = lo; s <= hi; s++) {
    const ha = hashAt(a, s);
    const hb = hashAt(b, s);
    if (ha === null || hb === null) continue;
    if (ha === hb) {
      if (firstDiff !== null) fail('view hashes agree again after diverging at seq ' + firstDiff + ' (impossible for an honest hash chain; at least one view is fabricated)');
      lastEqual = s;
    } else if (firstDiff === null) firstDiff = s;
  }
  if (firstDiff !== null) {
    const exact = firstDiff === 1 || lastEqual === firstDiff - 1;
    return { ...base, verdict: 'fork', divergence_seq: firstDiff, divergence_exact: exact,
      detail: exact ? 'histories diverge at seq ' + firstDiff : 'histories differ at seq ' + firstDiff + ' (earliest seq both windows cover); divergence is at or before it' };
  }
  if (!kl.consistent) {
    return { ...base, verdict: 'fork', detail: 'key histories diverge at rotation index ' + kl.divergence_index + ' (event windows do not show where)' };
  }
  if (hi < lo && !(sa === 0 || sb === 0)) {
    // No overlapping event hashes (e.g. one bot only kept a pruned window far ahead).
    if (sa === sb && a.head.hash === b.head.hash) return { ...base, verdict: 'consistent', detail: 'same head' };
    return { ...base, verdict: 'undetermined', detail: 'windows do not overlap (a: ' + a.window.from_seq + '..' + sa + ', b: ' + b.window.from_seq + '..' + sb + '); exchange longer windows' };
  }
  if (sa === sb) {
    if (a.head.hash === b.head.hash) return { ...base, verdict: 'consistent', detail: 'same head seq ' + sa };
    return { ...base, verdict: 'fork', divergence_seq: sa, divergence_exact: false, detail: 'same head seq, different hash' };
  }
  // Different lengths and every overlapping hash agrees: the shorter view's
  // head must be covered by the longer view for a proven prefix.
  const shorter = sa < sb ? a : b;
  const longer = sa < sb ? b : a;
  const at = hashAt(longer, shorter.head.seq);
  if (at === null) return { ...base, verdict: 'undetermined', detail: 'the longer view pruned seq ' + shorter.head.seq + '; cannot check the shorter head' };
  if (at !== shorter.head.hash) return { ...base, verdict: 'fork', divergence_seq: shorter.head.seq, divergence_exact: false, detail: 'shorter head not in longer history' };
  if (shorter.key_log.length > longer.key_log.length) {
    return { ...base, verdict: 'fork', detail: 'shorter history has more rotations than the longer one' };
  }
  return { ...base, verdict: 'prefix', behind: sa < sb ? 'a' : 'b', detail: 'seq ' + shorter.head.seq + ' is a prefix of seq ' + longer.head.seq };
}

// Compare my view against several peer views. Each peer is
// { name, view, evidence: 'signed-feed' | 'view-summary' }. If my view is not
// pinned to the expected anchor the call fails (compare what you trust).
// Returns { overall, results: [{ peer, evidence, ...compareViews }] }.
// overall: 'fork' if any fork, else 'different_genesis' if any, else
// 'undetermined' if any, else 'consistent' (prefixes count as consistent).
export function comparePeers(mine, peers, opts = {}) {
  validateView(mine);
  if (opts.pin !== undefined && opts.pin !== null) {
    const norm = normalizePin(opts.pin);
    if (!norm) fail('pin must be an anchor fingerprint (hf2:... >= 32 hex)', 'HIVE_BAD_PIN');
    if (!mine.anchor.startsWith(norm)) fail('my view is not for the pinned anchor', 'HIVE_ANCHOR_MISMATCH');
  }
  const results = peers.map((p) => {
    const r = compareViews(mine, p.view);
    const proven = r.verdict === 'fork' && p.evidence === 'signed-feed' && opts.mineEvidence === 'signed-feed';
    return { peer: p.name, evidence: p.evidence, proven, ...r };
  });
  const has = (v) => results.some((r) => r.verdict === v);
  const overall = has('fork') ? 'fork' : has('different_genesis') ? 'different_genesis' : has('undetermined') ? 'undetermined' : 'consistent';
  return { overall, results };
}
