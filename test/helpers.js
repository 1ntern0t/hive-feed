// Test helpers. The key pair here is a THROWAWAY TEST KEY generated fresh at
// test time and kept in memory only. It is never written to the repo.
import { generateKeyPair, importPrivateKey, emptyFeed, appendEvent, serializeFeed, signFeedBytes } from '../src/index.js';

export const NOW = new Date('2026-10-25T12:00:00.000Z');

export function testKey() {
  const { publicKey, privateKeyPem } = generateKeyPair();
  return { publicKey, priv: importPrivateKey(privateKeyPem) };
}

export function buildFeed(key, n = 3, opts = {}) {
  let feed = emptyFeed(opts.feedId || 'test-feed', key.publicKey, NOW);
  for (let i = 1; i <= n; i++) {
    const ts = new Date(NOW.getTime() - (n - i + 1) * 60000).toISOString();
    feed = appendEvent(feed, key.priv, {
      type: opts.type || 'task',
      id: (opts.idPrefix || 'ev-') + i,
      ts,
      channel: 'build-challenge',
      poster_id: opts.poster || 'U-GIGATRON',
      url: 'https://example.org/t/' + i,
      text: opts.text ? opts.text(i) : 'event number ' + i
    }, { now: NOW, keep: opts.keep || 0 });
  }
  return feed;
}

export function signed(key, feed) {
  const bytes = Buffer.from(serializeFeed(feed), 'utf8');
  return { bytes, sig: signFeedBytes(key.priv, bytes) };
}

// Re-sign arbitrary bytes (simulates an attacker who HAS the key, or a
// publisher bug), so we can test chain checks independently of the file sig.
export function resignRaw(key, str) {
  const bytes = Buffer.from(str, 'utf8');
  return { bytes, sig: signFeedBytes(key.priv, bytes) };
}
