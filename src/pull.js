import { verifyFeedDetailed, DEFAULT_LIMITS } from './feed.js';
import { checkPin } from './anchor.js';
import { applyFeed, emptyState } from './consumer.js';

export const DEFAULT_PULL = Object.freeze({
  timeoutMs: 10000,
  maxBytes: DEFAULT_LIMITS.maxBytes,
  maxSigBytes: 256
});

async function readLimited(res, maxBytes) {
  const len = Number(res.headers.get('content-length'));
  if (Number.isFinite(len) && len > maxBytes) throw Object.assign(new Error('response too large (' + len + ' > ' + maxBytes + ')'), { code: 'HIVE_TOO_LARGE' });
  if (!res.body) return Buffer.alloc(0);
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel().catch(() => {});
      throw Object.assign(new Error('response exceeded ' + maxBytes + ' bytes'), { code: 'HIVE_TOO_LARGE' });
    }
    chunks.push(Buffer.from(value));
  }
  return Buffer.concat(chunks);
}

function checkUrl(u, allowHttp) {
  const url = new URL(u);
  if (url.protocol === 'https:') return url;
  if (allowHttp && url.protocol === 'http:') return url;
  throw Object.assign(new Error('refusing non-https URL: ' + url.protocol), { code: 'HIVE_BAD_URL' });
}

// The detached signature lives next to the feed: append ".sig" to the path, not to the end of
// the string, so "feed.json?v=3" maps to "feed.json.sig?v=3" (not "feed.json?v=3.sig").
export function defaultSigUrl(u, allowHttp) {
  const url = checkUrl(u, allowHttp);
  url.pathname += '.sig';
  url.hash = '';
  return url;
}

async function get(url, { timeoutMs, maxBytes, headers = {}, allowHttp, fetchImpl }) {
  const res = await fetchImpl(url, {
    method: 'GET',
    headers: { accept: 'application/json, application/x-ndjson, text/plain', ...headers },
    redirect: 'follow',
    signal: AbortSignal.timeout(timeoutMs)
  });
  if (res.url) checkUrl(res.url, allowHttp);
  if (res.status === 304) return { status: 304, etag: res.headers.get('etag') };
  if (res.status !== 200) throw Object.assign(new Error('HTTP ' + res.status + ' for ' + url), { code: 'HIVE_HTTP' });
  const body = await readLimited(res, maxBytes);
  return { status: 200, body, etag: res.headers.get('etag') };
}

// Pull a feed: conditional GET (ETag), fetch detached signature, verify
// against the pinned anchor, apply consumer policy. Returns
// { changed, accepted, skipped, warnings, keyChanges, state }. On any error the
// caller should keep its old state (fail closed).
//
// Pin: opts.pin (anchor fingerprint, or base64 genesis key; opts.publicKey is
// accepted as an alias). If none is given, the anchor saved in state from an
// earlier pull is used. With no pin at all the pull is refused (HIVE_UNPINNED)
// unless opts.allowUnpinned is set, in which case a loud warning is returned
// and the anchor is saved (trust on first use).
export async function pull(opts) {
  // Undefined options (e.g. CLI flags not given) must not override defaults.
  const given = Object.fromEntries(Object.entries(opts || {}).filter(([, v]) => v !== undefined));
  const o = { ...DEFAULT_PULL, ...given };
  const fetchImpl = o.fetchImpl || globalThis.fetch;
  const state = { ...emptyState(), ...(o.state || {}) };
  const feedUrl = checkUrl(o.url, o.allowHttp);
  if (o.sinceParam) feedUrl.searchParams.set(o.sinceParam, String(state.seq));
  const sigUrl = o.sigUrl ? checkUrl(o.sigUrl, o.allowHttp) : defaultSigUrl(o.url, o.allowHttp);

  const headers = state.etag ? { 'if-none-match': state.etag } : {};
  const feedRes = await get(feedUrl.href, { ...o, fetchImpl, headers, maxBytes: o.maxBytes });
  if (feedRes.status === 304) return { changed: false, accepted: [], skipped: [], warnings: [], state };

  const sigRes = await get(sigUrl.href, { ...o, fetchImpl, maxBytes: o.maxSigBytes });
  const sig = sigRes.body.toString('utf8').trim();
  const pin = o.pin || o.publicKey || state.anchor || null;
  const v = verifyFeedDetailed(feedRes.body, sig, pin, { maxBytes: o.maxBytes, maxEvents: o.maxEvents, allowUnpinned: !!o.allowUnpinned });
  if (state.anchor && pin !== state.anchor) checkPin(state.anchor, v.feed.genesis); // explicit pin must agree with saved anchor
  const result = applyFeed(state, v.feed, o.policy || {});
  result.state.etag = feedRes.etag || null;
  result.warnings = [...v.warnings, ...result.warnings];
  // bytes/sig are returned so a bot can keep the verified file for peer comparison.
  return { changed: true, fingerprint: v.fingerprint, fingerprintDisplay: v.fingerprintDisplay, bytes: feedRes.body, sig, ...result };
}
