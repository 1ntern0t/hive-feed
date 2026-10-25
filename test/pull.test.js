import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { createHash } from 'node:crypto';
import { pull, emptyState, appendEvent, serializeFeed, signFeedBytes } from '../src/index.js';
import { testKey, buildFeed, signed, NOW } from './helpers.js';

const key = testKey();
const POLICY = { trustedPosters: ['U-GIGATRON'], now: NOW };

function serve(routes) {
  return new Promise((resolve) => {
    const hits = [];
    const srv = createServer((req, res) => {
      hits.push({ url: req.url, inm: req.headers['if-none-match'] });
      const path = req.url.split('?')[0];
      const r = routes[path];
      if (!r) {
        res.writeHead(404).end();
        return;
      }
      if (r.slow) return; // never respond
      const body = typeof r.body === 'function' ? r.body() : r.body;
      const etag = '"' + createHash('sha256').update(body).digest('hex').slice(0, 16) + '"';
      if (req.headers['if-none-match'] === etag) {
        res.writeHead(304, { etag }).end();
        return;
      }
      const headers = { etag };
      if (r.noLength) headers['transfer-encoding'] = 'chunked';
      res.writeHead(200, headers);
      res.end(body);
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, base: 'http://127.0.0.1:' + srv.address().port, hits }));
  });
}

test('pull verifies, applies, and uses ETag for 304', async () => {
  let feed = buildFeed(key, 2);
  let cur = signed(key, feed);
  const { srv, base, hits } = await serve({
    '/feed.json': { body: () => cur.bytes },
    '/feed.json.sig': { body: () => cur.sig }
  });
  try {
    const opts = { url: base + '/feed.json', publicKey: key.publicKey, policy: POLICY, allowHttp: true };
    const r1 = await pull({ ...opts, state: emptyState() });
    assert.equal(r1.accepted.length, 2);
    assert.ok(r1.state.etag);
    const r2 = await pull({ ...opts, state: r1.state });
    assert.equal(r2.changed, false);
    assert.equal(hits[hits.length - 1].inm, r1.state.etag);
    feed = appendEvent(feed, key.priv, { type: 'dao_vote', id: 'vote-1', ts: NOW.toISOString(), channel: 'dao', poster_id: 'U-GIGATRON', text: 'vote' }, { now: NOW });
    cur = signed(key, feed);
    const r3 = await pull({ ...opts, state: r2.state, sinceParam: 'since' });
    assert.deepEqual(r3.accepted.map((e) => e.id), ['vote-1']);
    assert.ok(hits.some((h) => h.url === '/feed.json?since=2'));
  } finally {
    srv.close();
  }
});

test('pull rejects a feed with a bad signature', async () => {
  const cur = signed(key, buildFeed(key, 2));
  const other = testKey();
  const { srv, base } = await serve({
    '/feed.json': { body: cur.bytes },
    '/feed.json.sig': { body: signFeedBytes(other.priv, cur.bytes) }
  });
  try {
    await assert.rejects(pull({ url: base + '/feed.json', publicKey: key.publicKey, policy: POLICY, allowHttp: true }), { code: 'HIVE_BAD_SIGNATURE' });
  } finally {
    srv.close();
  }
});

test('pull enforces size limit (content-length and streamed)', async () => {
  const big = Buffer.alloc(300000, 0x20);
  const { srv, base } = await serve({
    '/big.json': { body: big },
    '/big.json.sig': { body: 'x' }
  });
  try {
    await assert.rejects(pull({ url: base + '/big.json', publicKey: key.publicKey, maxBytes: 1000, allowHttp: true }), { code: 'HIVE_TOO_LARGE' });
  } finally {
    srv.close();
  }
});

test('pull enforces time limit', async () => {
  const { srv, base } = await serve({ '/slow.json': { slow: true } });
  try {
    await assert.rejects(pull({ url: base + '/slow.json', publicKey: key.publicKey, timeoutMs: 300, allowHttp: true }), (e) => /timeout|abort/i.test(e.name + e.message));
  } finally {
    srv.closeAllConnections();
    srv.close();
  }
});

test('pull refuses plain http unless allowHttp', async () => {
  await assert.rejects(pull({ url: 'http://example.org/feed.json', publicKey: key.publicKey }), { code: 'HIVE_BAD_URL' });
  await assert.rejects(pull({ url: 'file:///etc/passwd', publicKey: key.publicKey, allowHttp: true }), { code: 'HIVE_BAD_URL' });
});

test('pull with rollback server response fails closed', async () => {
  const feedOld = buildFeed(key, 2);
  const feedNew = appendEvent(feedOld, key.priv, { type: 'task', id: 'n', ts: NOW.toISOString(), channel: 'c', poster_id: 'U-GIGATRON', text: 'n' }, { now: NOW });
  let cur = signed(key, feedNew);
  const { srv, base } = await serve({
    '/feed.json': { body: () => cur.bytes },
    '/feed.json.sig': { body: () => cur.sig }
  });
  try {
    const opts = { url: base + '/feed.json', publicKey: key.publicKey, policy: POLICY, allowHttp: true };
    const r1 = await pull({ ...opts, state: emptyState() });
    cur = { bytes: Buffer.from(serializeFeed(feedOld)), sig: signFeedBytes(key.priv, Buffer.from(serializeFeed(feedOld))) };
    await assert.rejects(pull({ ...opts, state: r1.state }), { code: 'HIVE_ROLLBACK' });
  } finally {
    srv.close();
  }
});
