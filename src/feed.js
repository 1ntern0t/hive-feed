import { canonicalize } from './canonical.js';
import {
  FORMAT, GENESIS_HASH, validateEventShape, eventHash, eventSigningBytes, textDigest
} from './event.js';
import { signBytes, verifyBytes, importPublicKey, keyId, publicKeyFromPrivate } from './keys.js';

export const DEFAULT_LIMITS = Object.freeze({
  maxBytes: 1024 * 1024,
  maxEvents: 5000
});

const FEED_FIELDS = new Set(['format', 'feed_id', 'key_id', 'updated', 'head', 'events']);
const RE_FEED_ID = /^[A-Za-z0-9._:-]{1,128}$/;

function fail(msg, code = 'HIVE_INVALID_FEED') {
  const err = new Error(msg);
  err.code = code;
  throw err;
}

export function emptyFeed(feedId, publicKeyB64, now = new Date()) {
  if (!RE_FEED_ID.test(feedId)) fail('feed_id: invalid');
  return {
    format: FORMAT,
    feed_id: feedId,
    key_id: keyId(publicKeyB64),
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

export function appendEvent(feed, privateKey, input, opts = {}) {
  const now = opts.now || new Date();
  const pub = publicKeyFromPrivate(privateKey);
  if (keyId(pub) !== feed.key_id) fail('append: private key does not match feed key_id');
  const text = input.text === undefined ? undefined : String(input.text);
  const ev = {
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
  if (!ev.text_digest) fail('append: need text or text_digest');
  if (text !== undefined && opts.includeText !== false) ev.text = text;
  ev.hash = eventHash(ev);
  ev.sig = signBytes(privateKey, eventSigningBytes(ev));
  validateEventShape(ev);
  const last = feed.events[feed.events.length - 1];
  if (last && Date.parse(ev.ts) < Date.parse(last.ts)) fail('append: ts must not go backwards');
  if (feed.events.some((e) => e.id === ev.id)) fail('append: duplicate id in window');
  const events = [...feed.events, ev];
  const keep = opts.keep || 0;
  const next = {
    ...feed,
    updated: now.toISOString(),
    head: { seq: ev.seq, hash: ev.hash },
    events: keep > 0 ? events.slice(-keep) : events
  };
  return next;
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
  if (feed.format !== FORMAT) fail('feed: unsupported format');
  if (typeof feed.feed_id !== 'string' || !RE_FEED_ID.test(feed.feed_id)) fail('feed: bad feed_id');
  if (typeof feed.key_id !== 'string' || !/^[0-9a-f]{16}$/.test(feed.key_id)) fail('feed: bad key_id');
  if (typeof feed.updated !== 'string' || !Number.isFinite(Date.parse(feed.updated))) fail('feed: bad updated');
  const h = feed.head;
  if (!h || typeof h !== 'object' || Object.keys(h).sort().join() !== 'hash,seq') fail('feed: bad head');
  if (!Number.isSafeInteger(h.seq) || h.seq < 0 || !/^[0-9a-f]{64}$/.test(h.hash)) fail('feed: bad head');
  if (!Array.isArray(feed.events)) fail('feed: events must be an array');
  if (feed.events.length > lim.maxEvents) fail('feed: too many events', 'HIVE_TOO_LARGE');
}

// Verifies: detached signature over the exact bytes, canonical form, key_id,
// every event's shape/hash/signature, contiguous seq, prev_hash chain,
// non-decreasing ts, unique ids, and head == last event.
// Returns the parsed feed. Throws on any failure (fail closed).
export function verifyFeed(bytes, sigB64, publicKeyB64, limits = {}) {
  const pubKey = importPublicKey(publicKeyB64);
  const buf = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), 'utf8');
  const lim = { ...DEFAULT_LIMITS, ...limits };
  if (buf.length > lim.maxBytes) fail('feed: ' + buf.length + ' bytes exceeds limit ' + lim.maxBytes, 'HIVE_TOO_LARGE');
  if (!verifyBytes(pubKey, buf, sigB64)) fail('feed: detached signature does not verify', 'HIVE_BAD_SIGNATURE');
  const feed = parseFeed(buf, lim);
  if (feed.key_id !== keyId(publicKeyB64.trim())) fail('feed: key_id does not match pinned key', 'HIVE_BAD_SIGNATURE');
  const ids = new Set();
  let prev = null;
  for (const ev of feed.events) {
    try {
      validateEventShape(ev);
    } catch (e) {
      fail('event seq ' + ev?.seq + ': ' + e.message);
    }
    if (eventHash(ev) !== ev.hash) fail('event seq ' + ev.seq + ': hash mismatch', 'HIVE_TAMPERED');
    if (!verifyBytes(pubKey, eventSigningBytes(ev), ev.sig)) fail('event seq ' + ev.seq + ': bad signature', 'HIVE_BAD_SIGNATURE');
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
  return feed;
}
