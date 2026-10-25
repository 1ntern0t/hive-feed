import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';

export const FORMAT = 'hive-feed/2';
export const EVENT_TYPES = Object.freeze(['task', 'speed_ping', 'dao_vote', 'announcement', 'result', 'rotate']);
export const GENESIS_HASH = '0'.repeat(64);
export const EVENT_SIG_DOMAIN = 'hive-feed/2:event:';
export const COSIGN_DOMAIN = 'hive-feed/2:cosign:';
export const MAX_TEXT_CHARS = 4000;
export const MAX_URL_CHARS = 2048;
export const MAX_GRACE_EVENTS = 10000;

const BODY_FIELDS = ['type', 'id', 'ts', 'channel', 'poster_id', 'url', 'text_digest', 'seq', 'prev_hash'];
const ALL_FIELDS = new Set([...BODY_FIELDS, 'rotate', 'text', 'hash', 'sig', 'cosig']);
const ROTATE_FIELDS = ['grace_events', 'grace_until', 'mode', 'next_pubkey', 'next_recovery_digest', 'prev_key_id', 'recovery_pubkey'];
const RE_B64KEY = /^[A-Za-z0-9+/]{43}=$/;
const RE_B64SIG = /^[A-Za-z0-9+/]{86}==$/;

const RE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const RE_CHANNEL = /^[A-Za-z0-9._#-]{1,80}$/;
const RE_POSTER = /^[A-Za-z0-9._:-]{1,64}$/;
const RE_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
const RE_HEX64 = /^[0-9a-f]{64}$/;
const RE_KEYID = /^[0-9a-f]{16}$/;
export const RE_TS_STRICT = RE_TS;

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function textDigest(text) {
  return sha256Hex(Buffer.from(String(text), 'utf8'));
}

function fail(msg) {
  const err = new Error(msg);
  err.code = 'HIVE_INVALID_EVENT';
  throw err;
}

export function validateUrl(url) {
  if (url === '') return;
  if (typeof url !== 'string' || url.length > MAX_URL_CHARS) fail('url: must be a string <= ' + MAX_URL_CHARS + ' chars');
  let u;
  try {
    u = new URL(url);
  } catch {
    fail('url: not a valid URL');
  }
  if (u.protocol !== 'https:') fail('url: only https: URLs (or empty string) are allowed');
  if (u.username || u.password) fail('url: credentials in URL are not allowed');
}

// Validates shape only (no crypto). Throws on the first problem.
export function validateEventShape(ev) {
  if (ev === null || typeof ev !== 'object' || Array.isArray(ev)) fail('event: must be an object');
  for (const k of Object.keys(ev)) if (!ALL_FIELDS.has(k)) fail('event: unknown field ' + JSON.stringify(k));
  for (const k of [...BODY_FIELDS, 'hash', 'sig']) if (!(k in ev)) fail('event: missing field ' + k);
  if (!EVENT_TYPES.includes(ev.type)) fail('type: must be one of ' + EVENT_TYPES.join('|'));
  if (typeof ev.id !== 'string' || !RE_ID.test(ev.id)) fail('id: invalid');
  if (typeof ev.ts !== 'string' || !RE_TS.test(ev.ts) || !Number.isFinite(Date.parse(ev.ts))) fail('ts: must be ISO-8601 UTC (YYYY-MM-DDTHH:MM:SS[.sss]Z)');
  if (typeof ev.channel !== 'string' || !RE_CHANNEL.test(ev.channel)) fail('channel: invalid');
  if (typeof ev.poster_id !== 'string' || !RE_POSTER.test(ev.poster_id)) fail('poster_id: invalid');
  validateUrl(ev.url);
  if (typeof ev.text_digest !== 'string' || !RE_HEX64.test(ev.text_digest)) fail('text_digest: must be 64 lowercase hex chars');
  if (!Number.isSafeInteger(ev.seq) || ev.seq < 1) fail('seq: must be a positive integer');
  if (typeof ev.prev_hash !== 'string' || !RE_HEX64.test(ev.prev_hash)) fail('prev_hash: must be 64 lowercase hex chars');
  if (typeof ev.hash !== 'string' || !RE_HEX64.test(ev.hash)) fail('hash: must be 64 lowercase hex chars');
  if (typeof ev.sig !== 'string') fail('sig: must be a base64 string');
  if (ev.type === 'rotate') {
    if (!('rotate' in ev) || !('cosig' in ev)) fail('rotate: event needs rotate and cosig fields');
    validateRotateShape(ev.rotate);
    if (typeof ev.cosig !== 'string' || !RE_B64SIG.test(ev.cosig)) fail('cosig: must be a 64-byte base64 signature');
  } else if ('rotate' in ev || 'cosig' in ev) {
    fail('rotate/cosig fields are only allowed on rotate events');
  }
  if ('text' in ev) {
    if (typeof ev.text !== 'string') fail('text: must be a string');
    if (ev.text.length > MAX_TEXT_CHARS) fail('text: longer than ' + MAX_TEXT_CHARS + ' chars');
    if (textDigest(ev.text) !== ev.text_digest) fail('text: does not match text_digest');
  }
}

// Shape of the rotate payload. Crypto and key-history checks live in feed.js.
export function validateRotateShape(r) {
  if (r === null || typeof r !== 'object' || Array.isArray(r)) fail('rotate: must be an object');
  if (Object.keys(r).sort().join() !== ROTATE_FIELDS.join()) fail('rotate: fields must be exactly ' + ROTATE_FIELDS.join(','));
  if (r.mode !== 'normal' && r.mode !== 'recovery') fail('rotate.mode: must be normal|recovery');
  if (typeof r.prev_key_id !== 'string' || !RE_KEYID.test(r.prev_key_id)) fail('rotate.prev_key_id: must be 16 hex chars');
  if (typeof r.next_pubkey !== 'string' || !RE_B64KEY.test(r.next_pubkey)) fail('rotate.next_pubkey: must be a base64 Ed25519 public key');
  if (!Number.isSafeInteger(r.grace_events) || r.grace_events < 0 || r.grace_events > MAX_GRACE_EVENTS) fail('rotate.grace_events: integer 0..' + MAX_GRACE_EVENTS);
  if (r.grace_until !== '' && (typeof r.grace_until !== 'string' || !RE_TS.test(r.grace_until) || !Number.isFinite(Date.parse(r.grace_until)))) fail('rotate.grace_until: "" or ISO-8601 UTC');
  if (r.mode === 'normal') {
    if (r.recovery_pubkey !== '' || r.next_recovery_digest !== '') fail('rotate: normal rotation cannot use or change the recovery key');
  } else {
    if (typeof r.recovery_pubkey !== 'string' || !RE_B64KEY.test(r.recovery_pubkey)) fail('rotate.recovery_pubkey: must be a base64 Ed25519 public key');
    if (r.next_recovery_digest !== '' && (typeof r.next_recovery_digest !== 'string' || !RE_HEX64.test(r.next_recovery_digest))) fail('rotate.next_recovery_digest: "" or 64 hex chars');
    if (r.grace_events !== 0 || r.grace_until !== '') fail('rotate: recovery rotation has no grace window');
  }
}

export function eventBody(ev) {
  const body = {};
  for (const k of BODY_FIELDS) body[k] = ev[k];
  if (ev.type === 'rotate') body.rotate = ev.rotate;
  return body;
}

export function eventSigningBytes(ev) {
  return Buffer.from(EVENT_SIG_DOMAIN + canonicalize(eventBody(ev)), 'utf8');
}

// Countersignature by the NEXT key over the same body, different domain.
// Proves the publisher holds the key it is rotating to.
export function eventCosigningBytes(ev) {
  return Buffer.from(COSIGN_DOMAIN + canonicalize(eventBody(ev)), 'utf8');
}

export function eventHash(ev) {
  return sha256Hex(Buffer.from(canonicalize(eventBody(ev)), 'utf8'));
}
