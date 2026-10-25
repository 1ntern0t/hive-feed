import { canonicalize } from './canonical.js';
import {
  FORMAT, GENESIS_HASH, validateEventShape, eventHash, eventSigningBytes, eventCosigningBytes, textDigest
} from './event.js';
import { signBytes, verifyBytes, importPublicKey, keyId, publicKeyFromPrivate } from './keys.js';
import {
  makeGenesis, validateGenesis, anchorFingerprint, formatFingerprint, checkPin, publicKeyDigest
} from './anchor.js';

export const DEFAULT_LIMITS = Object.freeze({
  maxBytes: 1024 * 1024,
  maxEvents: 5000,
  maxRotations: 1000
});

const FEED_FIELDS = new Set(['format', 'feed_id', 'genesis', 'key_id', 'key_log', 'updated', 'head', 'events']);
const RE_FEED_ID = /^[A-Za-z0-9._:-]{1,128}$/;

function fail(msg, code = 'HIVE_INVALID_FEED') {
  const err = new Error(msg);
  err.code = code;
  throw err;
}

// opts.recoveryPubkey: optional base64 public key of an OFFLINE recovery key.
// Only its sha256 is committed in genesis; the key itself is revealed only
// when it is used to force a rotation.
export function emptyFeed(feedId, publicKeyB64, now = new Date(), opts = {}) {
  if (!RE_FEED_ID.test(feedId)) fail('feed_id: invalid');
  return {
    format: FORMAT,
    feed_id: feedId,
    genesis: makeGenesis(feedId, publicKeyB64, now, opts.recoveryPubkey || ''),
    key_id: keyId(publicKeyB64),
    key_log: [],
    updated: now.toISOString(),
    head: { seq: 0, hash: GENESIS_HASH },
    events: []
  };
}

// Serialization is canonical JSON plus a trailing newline. parseFeed()
// requires the input bytes to equal this exact serialization, which rules out
// duplicate keys, whitespace games and other malleability.
export function serializeFeed(feed) {
  return canonicalize(feed) + '\n';
}

// NDJSON variant: line 1 is the header (feed without events), then one
// canonical event per line.
export function serializeFeedNdjson(feed) {
  const { events, ...header } = feed;
  return [canonicalize(header), ...events.map(canonicalize)].join('\n') + '\n';
}

// ---------------------------------------------------------------------------
// Key schedule. Walks key_log from genesis and checks every rotation:
//   normal   signed by the key that is current at that point, countersigned by
//            the next key, may grant the old key a grace window
//   recovery signed by the pre-committed recovery key (its sha256 must equal
//            the committed digest), countersigned by the next key, no grace,
//            consumes the recovery key and may commit a new recovery digest
// Keys may never be reused (rotation replay). Throws on any problem.
export function keySchedule(genesis, keyLog) {
  validateGenesis(genesis);
  if (!Array.isArray(keyLog)) fail('key_log: must be an array');
  const genesisKey = { pubkey: genesis.pubkey, key: importPublicKey(genesis.pubkey), id: keyId(genesis.pubkey) };
  let cur = genesisKey;
  let recoveryDigest = genesis.recovery_digest;
  const used = new Set([genesis.pubkey]);
  const retired = [];
  const rotations = [];
  let prev = null;
  for (const ev of keyLog) {
    try {
      validateEventShape(ev);
    } catch (e) {
      fail('key_log seq ' + ev?.seq + ': ' + e.message, 'HIVE_BAD_ROTATION');
    }
    if (ev.type !== 'rotate') fail('key_log seq ' + ev.seq + ': only rotate events belong in key_log', 'HIVE_BAD_ROTATION');
    if (eventHash(ev) !== ev.hash) fail('key_log seq ' + ev.seq + ': hash mismatch', 'HIVE_TAMPERED');
    if (prev) {
      if (ev.hash === prev.hash || ev.id === prev.id) fail('key_log seq ' + ev.seq + ': rotation replayed', 'HIVE_ROTATION_REPLAY');
      if (ev.seq <= prev.seq) fail('key_log seq ' + ev.seq + ': rotations out of order', 'HIVE_ROTATION_REPLAY');
      if (Date.parse(ev.ts) < Date.parse(prev.ts)) fail('key_log seq ' + ev.seq + ': ts goes backwards', 'HIVE_BAD_ROTATION');
    }
    const r = ev.rotate;
    if (r.prev_key_id !== cur.id) fail('rotation seq ' + ev.seq + ': prev_key_id ' + r.prev_key_id + ' is not the current key ' + cur.id, 'HIVE_BAD_ROTATION');
    if (used.has(r.next_pubkey)) fail('rotation seq ' + ev.seq + ': next key was already used (rotation replay)', 'HIVE_ROTATION_REPLAY');
    if (recoveryDigest && publicKeyDigest(r.next_pubkey) === recoveryDigest) fail('rotation seq ' + ev.seq + ': must not rotate to the recovery key', 'HIVE_BAD_ROTATION');
    const next = { pubkey: r.next_pubkey, key: importPublicKey(r.next_pubkey), id: keyId(r.next_pubkey) };
    const body = eventSigningBytes(ev);
    if (r.mode === 'normal') {
      if (!verifyBytes(cur.key, body, ev.sig)) fail('rotation seq ' + ev.seq + ': not signed by the current key ' + cur.id, 'HIVE_BAD_ROTATION');
      if (r.grace_until !== '' && Date.parse(r.grace_until) < Date.parse(ev.ts)) fail('rotation seq ' + ev.seq + ': grace_until is before the rotation', 'HIVE_BAD_ROTATION');
    } else {
      if (!recoveryDigest) fail('rotation seq ' + ev.seq + ': no recovery key is committed', 'HIVE_BAD_ROTATION');
      if (publicKeyDigest(r.recovery_pubkey) !== recoveryDigest) fail('rotation seq ' + ev.seq + ': recovery key does not match the committed digest', 'HIVE_BAD_ROTATION');
      if (!verifyBytes(importPublicKey(r.recovery_pubkey), body, ev.sig)) fail('rotation seq ' + ev.seq + ': not signed by the recovery key', 'HIVE_BAD_ROTATION');
      if (r.next_recovery_digest === recoveryDigest) fail('rotation seq ' + ev.seq + ': recovery key cannot be re-committed (one use only)', 'HIVE_ROTATION_REPLAY');
      used.add(r.recovery_pubkey);
      recoveryDigest = r.next_recovery_digest;
    }
    if (!verifyBytes(next.key, eventCosigningBytes(ev), ev.cosig)) fail('rotation seq ' + ev.seq + ': missing or bad countersignature by the next key', 'HIVE_BAD_ROTATION');
    used.add(r.next_pubkey);
    retired.push(cur);
    rotations.push({
      seq: ev.seq, hash: ev.hash, ts: ev.ts, mode: r.mode, from: cur, to: next,
      graceLastSeq: r.mode === 'normal' ? ev.seq + r.grace_events : ev.seq,
      graceUntilMs: r.grace_until === '' ? Infinity : Date.parse(r.grace_until)
    });
    cur = next;
    prev = ev;
  }
  return { genesisKey, current: cur, recoveryDigest, rotations, retired };
}

// Keys allowed to sign a non-rotate event at (seq, ts).
export function signersFor(sched, seq, ts) {
  let rot = null;
  for (const r of sched.rotations) if (r.seq < seq) rot = r;
  if (!rot) return { current: sched.genesisKey, grace: null };
  const t = Date.parse(ts);
  const inGrace = rot.mode === 'normal' && seq <= rot.graceLastSeq && t <= rot.graceUntilMs;
  return { current: rot.to, grace: inGrace ? rot.from : null };
}

// Key that must sign a rotate event at seq (the current key, never a grace key).
function currentAt(sched, seq) {
  let k = sched.genesisKey;
  for (const r of sched.rotations) if (r.seq < seq) k = r.to;
  return k;
}

function buildEvent(feed, input, now, text) {
  return {
    type: input.type,
    id: input.id,
    ts: input.ts || now.toISOString(),
    channel: input.channel,
    poster_id: input.poster_id,
    url: input.url || '',
    text_digest: input.text_digest || (text !== undefined ? textDigest(text) : undefined),
    seq: feed.head.seq + 1,
    prev_hash: feed.head.hash
  };
}

function pushEvent(feed, ev, opts, now) {
  validateEventShape(ev);
  const last = feed.events[feed.events.length - 1];
  if (last && Date.parse(ev.ts) < Date.parse(last.ts)) fail('append: ts must not go backwards');
  if (feed.events.some((e) => e.id === ev.id)) fail('append: duplicate id in window');
  const events = [...feed.events, ev];
  const keep = opts.keep || 0;
  return {
    ...feed,
    updated: now.toISOString(),
    head: { seq: ev.seq, hash: ev.hash },
    events: keep > 0 ? events.slice(-keep) : events
  };
}

// privateKey must be the current key, or the previous key while the last
// rotation's grace window is still open for this seq/ts.
export function appendEvent(feed, privateKey, input, opts = {}) {
  const now = opts.now || new Date();
  if (input.type === 'rotate') fail('append: use rotateKey() or recoverKey() for rotate events');
  const pub = publicKeyFromPrivate(privateKey);
  const text = input.text === undefined ? undefined : String(input.text);
  const ev = buildEvent(feed, input, now, text);
  const sched = keySchedule(feed.genesis, feed.key_log);
  const { current, grace } = signersFor(sched, ev.seq, ev.ts);
  if (pub !== current.pubkey && !(grace && pub === grace.pubkey)) {
    fail('append: private key does not match feed key_id' + (sched.retired.some((k) => k.pubkey === pub) ? ' (key retired, grace window over)' : ''));
  }
  if (!ev.text_digest) fail('append: need text or text_digest');
  if (text !== undefined && opts.includeText !== false) ev.text = text;
  ev.hash = eventHash(ev);
  ev.sig = signBytes(privateKey, eventSigningBytes(ev));
  return pushEvent(feed, ev, opts, now);
}

function appendRotation(feed, signerPriv, nextPriv, input, rotate, opts) {
  const now = opts.now || new Date();
  const text = input.text === undefined ? 'publisher key rotation' : String(input.text);
  const ev = buildEvent(feed, { channel: 'announcements', poster_id: 'publisher', ...input, type: 'rotate', url: '' }, now, text);
  ev.rotate = rotate;
  if (opts.includeText !== false) ev.text = text;
  ev.hash = eventHash(ev);
  ev.sig = signBytes(signerPriv, eventSigningBytes(ev));
  ev.cosig = signBytes(nextPriv, eventCosigningBytes(ev));
  const logEntry = { ...ev };
  delete logEntry.text; // key_log keeps only the digest
  const keyLog = [...feed.key_log, logEntry];
  keySchedule(feed.genesis, keyLog); // refuse to produce an invalid history
  const next = pushEvent(feed, ev, opts, now);
  return { ...next, key_id: keyId(rotate.next_pubkey), key_log: keyLog };
}

// Normal rotation: signed by the CURRENT key, countersigned by the next key.
// input: { id, ts?, channel?, poster_id?, text?, graceEvents?, graceUntil? }
export function rotateKey(feed, currentPriv, nextPriv, input, opts = {}) {
  const sched = keySchedule(feed.genesis, feed.key_log);
  const cur = currentAt(sched, feed.head.seq + 1);
  if (publicKeyFromPrivate(currentPriv) !== cur.pubkey) fail('rotate: signing key is not the current key ' + cur.id);
  return appendRotation(feed, currentPriv, nextPriv, input, {
    mode: 'normal',
    prev_key_id: cur.id,
    next_pubkey: publicKeyFromPrivate(nextPriv),
    grace_events: input.graceEvents || 0,
    grace_until: input.graceUntil || '',
    recovery_pubkey: '',
    next_recovery_digest: ''
  }, opts);
}

// Forced rotation with the pre-committed offline recovery key, for when the
// current key is lost or stolen. No grace: the old key is rejected from the
// next event on. input.nextRecoveryPubkey commits a fresh recovery key.
export function recoverKey(feed, recoveryPriv, nextPriv, input, opts = {}) {
  const sched = keySchedule(feed.genesis, feed.key_log);
  const cur = currentAt(sched, feed.head.seq + 1);
  return appendRotation(feed, recoveryPriv, nextPriv, input, {
    mode: 'recovery',
    prev_key_id: cur.id,
    next_pubkey: publicKeyFromPrivate(nextPriv),
    grace_events: 0,
    grace_until: '',
    recovery_pubkey: publicKeyFromPrivate(recoveryPriv),
    next_recovery_digest: input.nextRecoveryPubkey ? publicKeyDigest(input.nextRecoveryPubkey) : ''
  }, opts);
}

export function signFeedBytes(privateKey, bytes) {
  return signBytes(privateKey, bytes);
}

export function parseFeed(bytes, limits = {}) {
  const lim = { ...DEFAULT_LIMITS, ...limits };
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), 'utf8');
  if (buf.length > lim.maxBytes) fail('feed: ' + buf.length + ' bytes exceeds limit ' + lim.maxBytes, 'HIVE_TOO_LARGE');
  let str;
  try {
    str = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buf);
  } catch {
    fail('feed: invalid UTF-8');
  }
  let feed;
  let ndjson = false;
  try {
    feed = JSON.parse(str);
    if (feed !== null && typeof feed === 'object' && !Array.isArray(feed) && !('events' in feed)) {
      // Header-only NDJSON feed (no events yet).
      feed.events = [];
      ndjson = true;
    }
  } catch {
    const lines = str.split('\n');
    if (lines[lines.length - 1] === '') lines.pop();
    if (lines.length === 0) fail('feed: empty');
    if (lines.length - 1 > lim.maxEvents) fail('feed: too many events', 'HIVE_TOO_LARGE');
    try {
      feed = JSON.parse(lines[0]);
      if (feed === null || typeof feed !== 'object' || 'events' in feed) throw new Error();
      feed.events = lines.slice(1).map((l) => JSON.parse(l));
    } catch {
      fail('feed: not valid JSON or NDJSON');
    }
    ndjson = true;
  }
  checkFeedShape(feed, lim);
  let canonical;
  try {
    canonical = ndjson ? serializeFeedNdjson(feed) : serializeFeed(feed);
  } catch (e) {
    fail('feed: not canonical (' + e.message + ')');
  }
  if (canonical !== str) fail('feed: bytes are not in canonical form');
  return feed;
}

function checkFeedShape(feed, lim) {
  if (feed === null || typeof feed !== 'object' || Array.isArray(feed)) fail('feed: must be an object');
  for (const k of Object.keys(feed)) if (!FEED_FIELDS.has(k)) fail('feed: unknown field ' + JSON.stringify(k));
  for (const k of FEED_FIELDS) if (!(k in feed)) fail('feed: missing field ' + k);
  if (feed.format !== FORMAT) fail('feed: unsupported format');
  if (typeof feed.feed_id !== 'string' || !RE_FEED_ID.test(feed.feed_id)) fail('feed: bad feed_id');
  if (typeof feed.key_id !== 'string' || !/^[0-9a-f]{16}$/.test(feed.key_id)) fail('feed: bad key_id');
  if (typeof feed.updated !== 'string' || !Number.isFinite(Date.parse(feed.updated))) fail('feed: bad updated');
  const h = feed.head;
  if (!h || typeof h !== 'object' || Object.keys(h).sort().join() !== 'hash,seq') fail('feed: bad head');
  if (!Number.isSafeInteger(h.seq) || h.seq < 0 || !/^[0-9a-f]{64}$/.test(h.hash)) fail('feed: bad head');
  if (!Array.isArray(feed.events)) fail('feed: events must be an array');
  if (feed.events.length > lim.maxEvents) fail('feed: too many events', 'HIVE_TOO_LARGE');
  if (!Array.isArray(feed.key_log)) fail('feed: key_log must be an array');
  if (feed.key_log.length > lim.maxRotations) fail('feed: too many rotations', 'HIVE_TOO_LARGE');
  validateGenesis(feed.genesis);
  if (feed.genesis.feed_id !== feed.feed_id) fail('feed: genesis.feed_id does not match feed_id');
}

// Full verification, fail closed. pin is one of:
//   anchor fingerprint "hf2:xxxx-..." (>= 128 bits) or 64 hex  (recommended)
//   base64 genesis public key                                  (v0.1 style)
//   null/undefined -> refused (HIVE_UNPINNED) unless opts.allowUnpinned
// Checks: pin vs genesis, the whole key history (key_log), the detached
// signature by the current key, canonical form, every event's
// shape/hash/signature (by the key valid at that seq, incl. grace rules),
// rotate events in the window == key_log entries, contiguous seq, prev_hash
// chain, non-decreasing ts, unique ids, and head == last event.
// Returns { feed, fingerprint, fingerprintDisplay, pinKind, keyId, rotations, warnings }.
export function verifyFeedDetailed(bytes, sigB64, pin, opts = {}) {
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), 'utf8');
  const lim = { ...DEFAULT_LIMITS, ...opts };
  if (buf.length > lim.maxBytes) fail('feed: ' + buf.length + ' bytes exceeds limit ' + lim.maxBytes, 'HIVE_TOO_LARGE');
  const warnings = [];
  const unpinned = pin === undefined || pin === null || pin === '';
  if (unpinned && !opts.allowUnpinned) {
    fail('no pinned anchor: refusing to trust the first feed we see. Get the anchor fingerprint out of band (operator announcement / QR) or opt in to unpinned TOFU mode explicitly.', 'HIVE_UNPINNED');
  }
  const feed = parseFeed(buf, lim);
  const pinInfo = unpinned ? { kind: 'unpinned', fingerprint: anchorFingerprint(feed.genesis) } : checkPin(pin, feed.genesis);
  if (unpinned) warnings.push('UNPINNED (TOFU): anchor ' + formatFingerprint(pinInfo.fingerprint) + ' was NOT checked against an out-of-band value; anyone could have produced this feed');
  if (pinInfo.kind === 'genesis-pubkey') warnings.push('pinned by genesis public key only; pin the anchor fingerprint ' + formatFingerprint(pinInfo.fingerprint) + ' to also commit to the recovery key');

  const sched = keySchedule(feed.genesis, feed.key_log);
  if (feed.key_id !== sched.current.id) fail('feed: key_id does not match the key history (expected ' + sched.current.id + ')', 'HIVE_BAD_SIGNATURE');
  if (!verifyBytes(sched.current.key, buf, sigB64)) fail('feed: detached signature does not verify with current key ' + sched.current.id, 'HIVE_BAD_SIGNATURE');

  const logBySeq = new Map(feed.key_log.map((e) => [e.seq, e]));
  for (const e of feed.key_log) if (e.seq > feed.head.seq) fail('key_log seq ' + e.seq + ': after head', 'HIVE_BAD_ROTATION');

  const ids = new Set();
  let prev = null;
  for (const ev of feed.events) {
    try {
      validateEventShape(ev);
    } catch (e) {
      fail('event seq ' + ev?.seq + ': ' + e.message);
    }
    if (eventHash(ev) !== ev.hash) fail('event seq ' + ev.seq + ': hash mismatch', 'HIVE_TAMPERED');
    const logged = logBySeq.get(ev.seq);
    if (ev.type === 'rotate') {
      // Signature, countersignature and key continuity were checked in keySchedule.
      if (!logged || logged.hash !== ev.hash || logged.sig !== ev.sig || logged.cosig !== ev.cosig) {
        fail('event seq ' + ev.seq + ': rotate event is not the one recorded in key_log', 'HIVE_BAD_ROTATION');
      }
    } else {
      if (logged) fail('event seq ' + ev.seq + ': key_log records a rotation at this seq', 'HIVE_BAD_ROTATION');
      const { current, grace } = signersFor(sched, ev.seq, ev.ts);
      const sb = eventSigningBytes(ev);
      if (!verifyBytes(current.key, sb, ev.sig) && !(grace && verifyBytes(grace.key, sb, ev.sig))) {
        if (sched.retired.some((k) => verifyBytes(k.key, sb, ev.sig))) fail('event seq ' + ev.seq + ': signed by a retired key outside its grace window', 'HIVE_KEY_RETIRED');
        fail('event seq ' + ev.seq + ': bad signature', 'HIVE_BAD_SIGNATURE');
      }
    }
    if (prev) {
      if (ev.seq !== prev.seq + 1) fail('event seq ' + ev.seq + ': not contiguous after ' + prev.seq, 'HIVE_BROKEN_CHAIN');
      if (ev.prev_hash !== prev.hash) fail('event seq ' + ev.seq + ': prev_hash does not link', 'HIVE_BROKEN_CHAIN');
      if (Date.parse(ev.ts) < Date.parse(prev.ts)) fail('event seq ' + ev.seq + ': ts goes backwards', 'HIVE_BROKEN_CHAIN');
    } else if (ev.seq === 1 && ev.prev_hash !== GENESIS_HASH) {
      fail('event seq 1: prev_hash must be genesis', 'HIVE_BROKEN_CHAIN');
    }
    if (ids.has(ev.id)) fail('event seq ' + ev.seq + ': duplicate id ' + JSON.stringify(ev.id), 'HIVE_REPLAY');
    ids.add(ev.id);
    prev = ev;
  }
  if (prev && (feed.head.seq !== prev.seq || feed.head.hash !== prev.hash)) {
    fail('feed: head does not match last event', 'HIVE_BROKEN_CHAIN');
  }
  if (!prev && feed.head.seq === 0 && feed.head.hash !== GENESIS_HASH) {
    fail('feed: empty feed must have genesis head', 'HIVE_BROKEN_CHAIN');
  }
  if (feed.events.length) {
    const lo = feed.events[0].seq;
    for (const e of feed.key_log) if (e.seq >= lo && !ids.has(e.id)) fail('key_log seq ' + e.seq + ': rotation missing from the event window', 'HIVE_BAD_ROTATION');
  }
  return {
    feed,
    fingerprint: pinInfo.fingerprint,
    fingerprintDisplay: formatFingerprint(pinInfo.fingerprint),
    pinKind: pinInfo.kind,
    keyId: sched.current.id,
    rotations: sched.rotations.map((r) => ({ seq: r.seq, mode: r.mode, from: r.from.id, to: r.to.id, graceLastSeq: r.graceLastSeq })),
    warnings
  };
}

// Returns the parsed feed. Throws on any failure (fail closed).
export function verifyFeed(bytes, sigB64, pin, opts = {}) {
  return verifyFeedDetailed(bytes, sigB64, pin, opts).feed;
}
