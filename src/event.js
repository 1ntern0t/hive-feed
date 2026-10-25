import { createHash } from 'node:crypto';
import { canonicalize } from './canonical.js';

export const FORMAT = 'hive-feed/1';
export const EVENT_TYPES = Object.freeze(['task', 'speed_ping', 'dao_vote', 'announcement', 'result']);
export const GENESIS_HASH = '0'.repeat(64);
export const EVENT_SIG_DOMAIN = 'hive-feed/1:event:';
export const MAX_TEXT_CHARS = 4000;
export const MAX_URL_CHARS = 2048;

const BODY_FIELDS = ['type', 'id', 'ts', 'channel', 'poster_id', 'url', 'text_digest', 'seq', 'prev_hash'];
const ALL_FIELDS = new Set([...BODY_FIELDS, 'text', 'hash', 'sig']);

const RE_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const RE_CHANNEL = /^[A-Za-z0-9._#-]{1,80}$/;
const RE_POSTER = /^[A-Za-z0-9._:-]{1,64}$/;
const RE_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
const RE_HEX64 = /^[0-9a-f]{64}$/;

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
  if ('text' in ev) {
    if (typeof ev.text !== 'string') fail('text: must be a string');
    if (ev.text.length > MAX_TEXT_CHARS) fail('text: longer than ' + MAX_TEXT_CHARS + ' chars');
    if (textDigest(ev.text) !== ev.text_digest) fail('text: does not match text_digest');
  }
}

export function eventBody(ev) {
  const body = {};
  for (const k of BODY_FIELDS) body[k] = ev[k];
  return body;
}

export function eventSigningBytes(ev) {
  return Buffer.from(EVENT_SIG_DOMAIN + canonicalize(eventBody(ev)), 'utf8');
}

export function eventHash(ev) {
  return sha256Hex(Buffer.from(canonicalize(eventBody(ev)), 'utf8'));
}
