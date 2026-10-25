// Trust anchor: the genesis record of a feed and its fingerprint.
//
// genesis = { created, feed_id, pubkey, recovery_digest }
//   pubkey           base64 raw Ed25519 key that signs the feed until the first rotation
//   recovery_digest  "" or hex sha256 of a raw recovery public key (pre-committed,
//                    the recovery private key stays offline)
//
// anchor fingerprint = sha256("hive-feed/2:anchor:" + canonical(genesis)), hex.
// The operator publishes it out of band (Mothership #announcements post, QR
// code, ...). It commits to the genesis key AND the recovery digest, so a
// thief of the genesis key cannot present a look-alike genesis with a
// different recovery key to a bot that pinned the fingerprint.
import { canonicalize } from './canonical.js';
import { sha256Hex, RE_TS_STRICT } from './event.js';

export const ANCHOR_DOMAIN = 'hive-feed/2:anchor:';
export const FP_PREFIX = 'hf2:';
// Short form shown to humans: 32 hex chars (128 bits) in groups of 4.
export const FP_SHORT_HEX = 32;
export const FP_MIN_PIN_HEX = 32;

const GENESIS_FIELDS = ['created', 'feed_id', 'pubkey', 'recovery_digest'];
const RE_FEED_ID = /^[A-Za-z0-9._:-]{1,128}$/;
const RE_B64KEY = /^[A-Za-z0-9+/]{43}=$/;

function fail(msg, code = 'HIVE_INVALID_FEED') {
  const err = new Error(msg);
  err.code = code;
  throw err;
}

export function publicKeyDigest(publicKeyB64) {
  return sha256Hex(Buffer.from(publicKeyB64.trim(), 'base64'));
}

export function makeGenesis(feedId, publicKeyB64, now = new Date(), recoveryPubkeyB64 = '') {
  const g = {
    created: now.toISOString(),
    feed_id: feedId,
    pubkey: publicKeyB64.trim(),
    recovery_digest: recoveryPubkeyB64 ? publicKeyDigest(recoveryPubkeyB64) : ''
  };
  validateGenesis(g);
  return g;
}

export function validateGenesis(g) {
  if (g === null || typeof g !== 'object' || Array.isArray(g)) fail('genesis: must be an object');
  if (Object.keys(g).sort().join() !== GENESIS_FIELDS.join()) fail('genesis: fields must be exactly ' + GENESIS_FIELDS.join(','));
  if (typeof g.created !== 'string' || !RE_TS_STRICT.test(g.created) || !Number.isFinite(Date.parse(g.created))) fail('genesis.created: ISO-8601 UTC');
  if (typeof g.feed_id !== 'string' || !RE_FEED_ID.test(g.feed_id)) fail('genesis.feed_id: invalid');
  if (typeof g.pubkey !== 'string' || !RE_B64KEY.test(g.pubkey)) fail('genesis.pubkey: must be a base64 Ed25519 public key');
  if (g.recovery_digest !== '' && (typeof g.recovery_digest !== 'string' || !/^[0-9a-f]{64}$/.test(g.recovery_digest))) fail('genesis.recovery_digest: "" or 64 hex chars');
}

export function anchorFingerprint(genesis) {
  validateGenesis(genesis);
  return sha256Hex(Buffer.from(ANCHOR_DOMAIN + canonicalize(genesis), 'utf8'));
}

// "hf2:1a2b-3c4d-..." (first 128 bits). Easy to read aloud and compare.
export function formatFingerprint(fullHex, hexChars = FP_SHORT_HEX) {
  return FP_PREFIX + fullHex.slice(0, hexChars).match(/.{4}/g).join('-');
}

// Accepts "hf2:xxxx-xxxx-...", plain hex, any case, with spaces/dashes/colons.
// Returns lowercase hex (>= 32 chars) or null if it is not a fingerprint.
export function normalizePin(pin) {
  if (typeof pin !== 'string') return null;
  let s = pin.trim().toLowerCase();
  if (s.startsWith(FP_PREFIX)) s = s.slice(FP_PREFIX.length);
  else if (/^hf\d+:/.test(s)) return null; // other format version
  s = s.replace(/[\s:-]/g, '');
  if (!/^[0-9a-f]+$/.test(s) || s.length < FP_MIN_PIN_HEX || s.length > 64) return null;
  return s;
}

export function isPublicKeyPin(pin) {
  return typeof pin === 'string' && RE_B64KEY.test(pin.trim());
}

// Compare a pin against a genesis record. Pin kinds:
//   fingerprint (recommended): must equal the start of the anchor fingerprint
//   base64 public key (v0.1 style): must equal genesis.pubkey; weaker because
//     it does not commit to the recovery digest
// Returns { kind, fingerprint }. Throws HIVE_ANCHOR_MISMATCH / HIVE_BAD_PIN.
export function checkPin(pin, genesis) {
  const fp = anchorFingerprint(genesis);
  const norm = normalizePin(pin);
  if (norm) {
    if (fp.slice(0, norm.length) !== norm) fail('anchor mismatch: feed genesis fingerprint ' + formatFingerprint(fp) + ' does not match pinned ' + FP_PREFIX + norm, 'HIVE_ANCHOR_MISMATCH');
    return { kind: 'fingerprint', fingerprint: fp };
  }
  if (isPublicKeyPin(pin)) {
    if (pin.trim() !== genesis.pubkey) fail('anchor mismatch: feed genesis key does not match pinned public key', 'HIVE_ANCHOR_MISMATCH');
    return { kind: 'genesis-pubkey', fingerprint: fp };
  }
  return fail('pin must be an anchor fingerprint (' + FP_PREFIX + '... with >= ' + FP_MIN_PIN_HEX + ' hex chars) or a base64 Ed25519 public key', 'HIVE_BAD_PIN');
}
