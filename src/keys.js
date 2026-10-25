import { generateKeyPairSync, createPublicKey, createPrivateKey, createHash, sign, verify } from 'node:crypto';

// Ed25519 SubjectPublicKeyInfo DER prefix; the raw 32-byte key follows it.
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

export function generateKeyPair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return {
    publicKey: exportPublicKey(publicKey),
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' })
  };
}

export function exportPublicKey(keyObject) {
  const der = keyObject.export({ type: 'spki', format: 'der' });
  return der.subarray(SPKI_PREFIX.length).toString('base64');
}

export function importPublicKey(b64) {
  if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/]{43}=$/.test(b64.trim())) {
    throw new Error('public key must be 32 raw bytes, base64 encoded');
  }
  const raw = Buffer.from(b64.trim(), 'base64');
  if (raw.length !== 32) throw new Error('public key must be 32 bytes');
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, raw]), format: 'der', type: 'spki' });
}

export function importPrivateKey(pem) {
  const key = createPrivateKey({ key: pem, format: 'pem' });
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('private key is not Ed25519');
  return key;
}

export function publicKeyFromPrivate(privateKey) {
  return exportPublicKey(createPublicKey(privateKey));
}

// key_id: first 16 hex chars of sha256(raw public key).
export function keyId(publicKeyB64) {
  return createHash('sha256').update(Buffer.from(publicKeyB64, 'base64')).digest('hex').slice(0, 16);
}

export function signBytes(privateKey, bytes) {
  return sign(null, Buffer.from(bytes), privateKey).toString('base64');
}

export function verifyBytes(publicKey, bytes, sigB64) {
  if (typeof sigB64 !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(sigB64.trim())) return false;
  const sig = Buffer.from(sigB64.trim(), 'base64');
  if (sig.length !== 64) return false;
  try {
    return verify(null, Buffer.from(bytes), publicKey, sig);
  } catch {
    return false;
  }
}
