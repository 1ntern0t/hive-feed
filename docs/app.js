// hive-feed/1 client-side verifier. No network, no innerHTML, no eval.
// All feed-derived strings reach the DOM only through textContent.
'use strict';
(function () {
  const FORMAT = 'hive-feed/1';
  const TYPES = ['task', 'speed_ping', 'dao_vote', 'announcement', 'result'];
  const GENESIS = '0'.repeat(64);
  const BODY = ['type', 'id', 'ts', 'channel', 'poster_id', 'url', 'text_digest', 'seq', 'prev_hash'];
  const EV_FIELDS = new Set(BODY.concat(['text', 'hash', 'sig']));
  const FEED_FIELDS = new Set(['format', 'feed_id', 'key_id', 'updated', 'head', 'events']);
  const MAX_BYTES = 1024 * 1024;
  const MAX_EVENTS = 5000;
  const enc = new TextEncoder();
  const $ = (id) => document.getElementById(id);

  function canon(v) {
    if (typeof v === 'string') return JSON.stringify(v);
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (typeof v === 'number') {
      if (!Number.isSafeInteger(v)) throw new Error('non-integer number');
      return String(v);
    }
    if (Array.isArray(v)) return '[' + v.map(canon).join(',') + ']';
    if (v && typeof v === 'object') {
      return '{' + Object.keys(v).sort().map((k) => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}';
    }
    throw new Error('unsupported value');
  }

  function hex(buf) {
    return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, '0')).join('');
  }
  async function sha256Hex(bytes) {
    return hex(await crypto.subtle.digest('SHA-256', bytes));
  }
  function b64(s) {
    const bin = atob(s.trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function body(ev) {
    const o = {};
    for (const k of BODY) o[k] = ev[k];
    return o;
  }

  function checkEvent(ev) {
    if (!ev || typeof ev !== 'object' || Array.isArray(ev)) throw new Error('event is not an object');
    for (const k of Object.keys(ev)) if (!EV_FIELDS.has(k)) throw new Error('unknown event field ' + JSON.stringify(k));
    for (const k of BODY.concat(['hash', 'sig'])) if (!(k in ev)) throw new Error('missing event field ' + k);
    if (!TYPES.includes(ev.type)) throw new Error('bad type');
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(ev.id)) throw new Error('bad id');
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.test(ev.ts) || !isFinite(Date.parse(ev.ts))) throw new Error('bad ts');
    if (!/^[A-Za-z0-9._#-]{1,80}$/.test(ev.channel)) throw new Error('bad channel');
    if (!/^[A-Za-z0-9._:-]{1,64}$/.test(ev.poster_id)) throw new Error('bad poster_id');
    if (ev.url !== '') {
      if (typeof ev.url !== 'string' || ev.url.length > 2048) throw new Error('bad url');
      const u = new URL(ev.url);
      if (u.protocol !== 'https:' || u.username || u.password) throw new Error('url must be https without credentials');
    }
    for (const k of ['text_digest', 'prev_hash', 'hash']) if (!/^[0-9a-f]{64}$/.test(ev[k])) throw new Error('bad ' + k);
    if (!Number.isSafeInteger(ev.seq) || ev.seq < 1) throw new Error('bad seq');
    if (typeof ev.sig !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(ev.sig)) throw new Error('bad event sig encoding');
    if ('text' in ev && (typeof ev.text !== 'string' || ev.text.length > 4000)) throw new Error('bad text');
  }

  async function verify(feedText, sigText, pubText) {
    if (!/^[A-Za-z0-9+/]{43}=$/.test(pubText.trim())) throw new Error('public key must be 32 bytes base64');
    if (!/^[A-Za-z0-9+/]{86}==$/.test(sigText.trim())) throw new Error('signature must be 64 bytes base64');
    if (!feedText.endsWith('\n')) feedText += '\n';
    const bytes = enc.encode(feedText);
    if (bytes.length > MAX_BYTES) throw new Error('feed larger than ' + MAX_BYTES + ' bytes');
    const raw = b64(pubText);
    const key = await crypto.subtle.importKey('raw', raw, { name: 'Ed25519' }, false, ['verify']);
    if (!(await crypto.subtle.verify({ name: 'Ed25519' }, key, b64(sigText), bytes))) throw new Error('detached signature does NOT verify');

    let feed;
    let nd = false;
    try {
      feed = JSON.parse(feedText);
      if (feed && typeof feed === 'object' && !('events' in feed)) {
        feed.events = [];
        nd = true;
      }
    } catch (e) {
      const lines = feedText.split('\n');
      lines.pop();
      if (lines.length - 1 > MAX_EVENTS) throw new Error('too many events');
      feed = JSON.parse(lines[0]);
      if (!feed || typeof feed !== 'object' || 'events' in feed) throw new Error('bad NDJSON header');
      feed.events = lines.slice(1).map((l) => JSON.parse(l));
      nd = true;
    }
    for (const k of Object.keys(feed)) if (!FEED_FIELDS.has(k)) throw new Error('unknown feed field ' + JSON.stringify(k));
    if (feed.format !== FORMAT) throw new Error('unsupported format');
    if (!Array.isArray(feed.events) || feed.events.length > MAX_EVENTS) throw new Error('bad events');
    const re = nd
      ? [canon(Object.fromEntries(Object.entries(feed).filter(([k]) => k !== 'events')))].concat(feed.events.map(canon)).join('\n') + '\n'
      : canon(feed) + '\n';
    if (re !== feedText) throw new Error('feed bytes are not canonical');
    const kid = (await sha256Hex(raw)).slice(0, 16);
    if (feed.key_id !== kid) throw new Error('key_id does not match pinned key');

    let prev = null;
    const ids = new Set();
    for (const ev of feed.events) {
      checkEvent(ev);
      const c = canon(body(ev));
      if ((await sha256Hex(enc.encode(c))) !== ev.hash) throw new Error('event ' + ev.seq + ': hash mismatch (tampered)');
      if (!(await crypto.subtle.verify({ name: 'Ed25519' }, key, b64(ev.sig), enc.encode('hive-feed/1:event:' + c)))) throw new Error('event ' + ev.seq + ': bad signature');
      if ('text' in ev && (await sha256Hex(enc.encode(ev.text))) !== ev.text_digest) throw new Error('event ' + ev.seq + ': text does not match digest');
      if (prev) {
        if (ev.seq !== prev.seq + 1 || ev.prev_hash !== prev.hash) throw new Error('event ' + ev.seq + ': broken chain');
        if (Date.parse(ev.ts) < Date.parse(prev.ts)) throw new Error('event ' + ev.seq + ': ts goes backwards');
      } else if (ev.seq === 1 && ev.prev_hash !== GENESIS) {
        throw new Error('event 1: prev_hash must be genesis');
      }
      if (ids.has(ev.id)) throw new Error('event ' + ev.seq + ': duplicate id (replay)');
      ids.add(ev.id);
      prev = ev;
    }
    if (prev && (feed.head.seq !== prev.seq || feed.head.hash !== prev.hash)) throw new Error('head does not match last event');
    return feed;
  }

  function cell(tr, text, cls) {
    const td = document.createElement('td');
    td.textContent = String(text);
    if (cls) td.className = cls;
    tr.appendChild(td);
  }

  function setStatus(ok, msg) {
    const s = $('status');
    s.className = ok ? 'ok' : 'bad';
    s.textContent = msg;
  }

  function render(feed) {
    const out = $('results');
    out.replaceChildren();
    const trusted = new Set($('trusted').value.split(',').map((x) => x.trim()).filter(Boolean));
    const maxAge = Number($('maxage').value) || 0;
    const now = Date.now();
    const warnings = [];
    if (feed.events.length && feed.events[0].seq > 1) warnings.push('Window starts at seq ' + feed.events[0].seq + '; earlier history was pruned and is not verified here.');
    if (!trusted.size) warnings.push('No verified poster IDs entered: every event is shown as untrusted.');
    if (now - Date.parse(feed.updated) > 7 * 86400000) warnings.push('Feed "updated" is more than 7 days old (stale or frozen feed?).');
    if (warnings.length) {
      const ul = document.createElement('ul');
      ul.className = 'warnings';
      for (const w of warnings) {
        const li = document.createElement('li');
        li.textContent = w;
        ul.appendChild(li);
      }
      out.appendChild(ul);
    }
    const table = document.createElement('table');
    const head = document.createElement('tr');
    for (const h of ['seq', 'type', 'id', 'ts', 'channel', 'poster_id', 'status', 'url', 'text (untrusted data)']) {
      const th = document.createElement('th');
      th.textContent = h;
      head.appendChild(th);
    }
    table.appendChild(head);
    for (const ev of feed.events) {
      const tr = document.createElement('tr');
      let st = 'trusted poster';
      if (!trusted.has(ev.poster_id)) st = 'UNTRUSTED poster';
      else if (maxAge && now - Date.parse(ev.ts) > maxAge * 1000) st = 'too old';
      else if (Date.parse(ev.ts) > now + 300000) st = 'future ts';
      cell(tr, ev.seq);
      cell(tr, ev.type);
      cell(tr, ev.id);
      cell(tr, ev.ts);
      cell(tr, ev.channel);
      cell(tr, ev.poster_id);
      cell(tr, st, st === 'trusted poster' ? '' : 'untrusted');
      cell(tr, ev.url);
      cell(tr, 'text' in ev ? ev.text : '(digest only) ' + ev.text_digest, 'text');
      table.appendChild(tr);
    }
    out.appendChild(table);
  }

  async function run() {
    $('results').replaceChildren();
    try {
      if (!(crypto && crypto.subtle)) throw new Error('WebCrypto unavailable (needs a secure context: https or file://)');
      const feed = await verify($('feed').value, $('sig').value, $('pubkey').value);
      setStatus(true, 'VALID: feed ' + feed.feed_id + ', key_id ' + feed.key_id + ', head seq ' + feed.head.seq + ', ' + feed.events.length + ' events in window. Signature, hashes and chain check out.');
      render(feed);
    } catch (e) {
      const msg = e && e.name === 'NotSupportedError' ? 'This browser does not support Ed25519 in WebCrypto.' : (e && e.message) || String(e);
      setStatus(false, 'REJECTED: ' + msg);
    }
  }

  $('verify').addEventListener('click', run);
  $('demo').addEventListener('click', () => {
    const d = window.HIVE_DEMO;
    if (!d) return setStatus(false, 'demo.js not loaded');
    $('feed').value = d.feed;
    $('sig').value = d.sig;
    $('pubkey').value = d.pubkey;
    $('trusted').value = d.trusted.join(',');
    run();
  });
  $('tamper').addEventListener('click', () => {
    const d = window.HIVE_DEMO;
    if (!d) return;
    $('feed').value = d.feed.replace('U-GIGATRON', 'U-GIGATRAN');
    $('sig').value = d.sig;
    $('pubkey').value = d.pubkey;
    run();
  });
  window.__hiveVerify = verify; // exposed for the headless test harness only
})();
