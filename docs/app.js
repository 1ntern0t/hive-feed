// hive-feed/2 client-side verifier. No network, no innerHTML, no eval.
// All feed-derived strings reach the DOM only through textContent.
// Mirrors src/feed.js: pinned anchor, key history (rotations, grace windows,
// recovery key), detached signature, per-event signatures and the hash chain.
'use strict';
(function () {
  const FORMAT = 'hive-feed/2';
  const TYPES = ['task', 'speed_ping', 'dao_vote', 'announcement', 'result', 'rotate'];
  const GENESIS = '0'.repeat(64);
  const BODY = ['type', 'id', 'ts', 'channel', 'poster_id', 'url', 'text_digest', 'seq', 'prev_hash'];
  const EV_FIELDS = new Set(BODY.concat(['rotate', 'text', 'hash', 'sig', 'cosig']));
  const FEED_FIELDS = ['events', 'feed_id', 'format', 'genesis', 'head', 'key_id', 'key_log', 'updated'];
  const GENESIS_FIELDS = 'created,feed_id,pubkey,recovery_digest';
  const ROTATE_FIELDS = 'grace_events,grace_until,mode,next_pubkey,next_recovery_digest,prev_key_id,recovery_pubkey';
  const MAX_BYTES = 1024 * 1024;
  const MAX_EVENTS = 5000;
  const MAX_ROTATIONS = 1000;
  const RE_TS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/;
  const RE_KEY = /^[A-Za-z0-9+/]{43}=$/;
  const RE_SIG = /^[A-Za-z0-9+/]{86}==$/;
  const RE_HEX = /^[0-9a-f]{64}$/;
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
    if (ev.type === 'rotate') o.rotate = ev.rotate;
    return o;
  }
  function isTs(t) {
    return typeof t === 'string' && RE_TS.test(t) && isFinite(Date.parse(t));
  }

  const keyCache = new Map();
  async function importKey(pubB64) {
    if (!keyCache.has(pubB64)) {
      keyCache.set(pubB64, {
        pubkey: pubB64,
        key: await crypto.subtle.importKey('raw', b64(pubB64), { name: 'Ed25519' }, false, ['verify']),
        id: (await sha256Hex(b64(pubB64))).slice(0, 16),
        digest: await sha256Hex(b64(pubB64))
      });
    }
    return keyCache.get(pubB64);
  }
  async function ver(k, sigB64, bytes) {
    if (typeof sigB64 !== 'string' || !RE_SIG.test(sigB64)) return false;
    return crypto.subtle.verify({ name: 'Ed25519' }, k.key, b64(sigB64), bytes);
  }

  function checkRotate(r) {
    if (!r || typeof r !== 'object' || Array.isArray(r) || Object.keys(r).sort().join() !== ROTATE_FIELDS) throw new Error('bad rotate fields');
    if (r.mode !== 'normal' && r.mode !== 'recovery') throw new Error('bad rotate.mode');
    if (!/^[0-9a-f]{16}$/.test(r.prev_key_id) || !RE_KEY.test(r.next_pubkey)) throw new Error('bad rotate keys');
    if (!Number.isSafeInteger(r.grace_events) || r.grace_events < 0 || r.grace_events > 10000) throw new Error('bad grace_events');
    if (r.grace_until !== '' && !isTs(r.grace_until)) throw new Error('bad grace_until');
    if (r.mode === 'normal' && (r.recovery_pubkey !== '' || r.next_recovery_digest !== '')) throw new Error('normal rotation cannot use or change the recovery key');
    if (r.mode === 'recovery') {
      if (!RE_KEY.test(r.recovery_pubkey)) throw new Error('bad recovery_pubkey');
      if (r.next_recovery_digest !== '' && !RE_HEX.test(r.next_recovery_digest)) throw new Error('bad next_recovery_digest');
      if (r.grace_events !== 0 || r.grace_until !== '') throw new Error('recovery rotation has no grace window');
    }
  }

  function checkEvent(ev) {
    if (!ev || typeof ev !== 'object' || Array.isArray(ev)) throw new Error('event is not an object');
    for (const k of Object.keys(ev)) if (!EV_FIELDS.has(k)) throw new Error('unknown event field ' + JSON.stringify(k));
    for (const k of BODY.concat(['hash', 'sig'])) if (!(k in ev)) throw new Error('missing event field ' + k);
    if (!TYPES.includes(ev.type)) throw new Error('bad type');
    if (!/^[A-Za-z0-9._:-]{1,128}$/.test(ev.id)) throw new Error('bad id');
    if (!isTs(ev.ts)) throw new Error('bad ts');
    if (!/^[A-Za-z0-9._#-]{1,80}$/.test(ev.channel)) throw new Error('bad channel');
    if (!/^[A-Za-z0-9._:-]{1,64}$/.test(ev.poster_id)) throw new Error('bad poster_id');
    if (ev.url !== '') {
      if (typeof ev.url !== 'string' || ev.url.length > 2048) throw new Error('bad url');
      const u = new URL(ev.url);
      if (u.protocol !== 'https:' || u.username || u.password) throw new Error('url must be https without credentials');
    }
    for (const k of ['text_digest', 'prev_hash', 'hash']) if (!RE_HEX.test(ev[k])) throw new Error('bad ' + k);
    if (!Number.isSafeInteger(ev.seq) || ev.seq < 1) throw new Error('bad seq');
    if (typeof ev.sig !== 'string' || !RE_SIG.test(ev.sig)) throw new Error('bad event sig encoding');
    if ('text' in ev && (typeof ev.text !== 'string' || ev.text.length > 4000)) throw new Error('bad text');
    if (ev.type === 'rotate') {
      if (!('rotate' in ev) || typeof ev.cosig !== 'string' || !RE_SIG.test(ev.cosig)) throw new Error('rotate event needs rotate and cosig');
      checkRotate(ev.rotate);
    } else if ('rotate' in ev || 'cosig' in ev) {
      throw new Error('rotate/cosig only allowed on rotate events');
    }
  }

  function checkGenesis(g, feedId) {
    if (!g || typeof g !== 'object' || Array.isArray(g) || Object.keys(g).sort().join() !== GENESIS_FIELDS) throw new Error('bad genesis fields');
    if (!isTs(g.created) || g.feed_id !== feedId || !RE_KEY.test(g.pubkey)) throw new Error('bad genesis');
    if (g.recovery_digest !== '' && !RE_HEX.test(g.recovery_digest)) throw new Error('bad genesis.recovery_digest');
  }

  async function fingerprint(genesis) {
    return sha256Hex(enc.encode('hive-feed/2:anchor:' + canon(genesis)));
  }
  function fpDisplay(full) {
    return 'hf2:' + full.slice(0, 32).match(/.{4}/g).join('-');
  }
  function normalizePin(pin) {
    let s = pin.trim().toLowerCase();
    if (s.startsWith('hf2:')) s = s.slice(4);
    else if (/^hf\d+:/.test(s)) return null;
    s = s.replace(/[\s:-]/g, '');
    if (!/^[0-9a-f]+$/.test(s) || s.length < 32 || s.length > 64) return null;
    return s;
  }

  // Same rules as keySchedule() in src/feed.js.
  async function keySchedule(genesis, log) {
    const gk = await importKey(genesis.pubkey);
    let cur = gk;
    let recDigest = genesis.recovery_digest;
    const used = new Set([genesis.pubkey]);
    const rotations = [];
    const retired = [];
    let prev = null;
    for (const ev of log) {
      checkEvent(ev);
      if (ev.type !== 'rotate') throw new Error('key_log: only rotate events allowed');
      const c = canon(body(ev));
      if ((await sha256Hex(enc.encode(c))) !== ev.hash) throw new Error('rotation ' + ev.seq + ': hash mismatch (tampered)');
      if (prev) {
        if (ev.hash === prev.hash || ev.id === prev.id || ev.seq <= prev.seq) throw new Error('rotation ' + ev.seq + ': replayed or out of order');
        if (Date.parse(ev.ts) < Date.parse(prev.ts)) throw new Error('rotation ' + ev.seq + ': ts goes backwards');
      }
      const r = ev.rotate;
      if (r.prev_key_id !== cur.id) throw new Error('rotation ' + ev.seq + ': prev_key_id is not the current key');
      if (used.has(r.next_pubkey)) throw new Error('rotation ' + ev.seq + ': next key already used (replay)');
      const next = await importKey(r.next_pubkey);
      if (recDigest && next.digest === recDigest) throw new Error('rotation ' + ev.seq + ': must not rotate to the recovery key');
      const sb = enc.encode('hive-feed/2:event:' + c);
      if (r.mode === 'normal') {
        if (!(await ver(cur, ev.sig, sb))) throw new Error('rotation ' + ev.seq + ': not signed by the current key');
        if (r.grace_until !== '' && Date.parse(r.grace_until) < Date.parse(ev.ts)) throw new Error('rotation ' + ev.seq + ': grace_until before rotation');
      } else {
        if (!recDigest) throw new Error('rotation ' + ev.seq + ': no recovery key committed');
        const rk = await importKey(r.recovery_pubkey);
        if (rk.digest !== recDigest) throw new Error('rotation ' + ev.seq + ': recovery key does not match committed digest');
        if (!(await ver(rk, ev.sig, sb))) throw new Error('rotation ' + ev.seq + ': not signed by the recovery key');
        if (r.next_recovery_digest === recDigest) throw new Error('rotation ' + ev.seq + ': recovery key reused');
        used.add(r.recovery_pubkey);
        recDigest = r.next_recovery_digest;
      }
      if (!(await ver(next, ev.cosig, enc.encode('hive-feed/2:cosign:' + c)))) throw new Error('rotation ' + ev.seq + ': bad countersignature by next key');
      used.add(r.next_pubkey);
      retired.push(cur);
      rotations.push({
        seq: ev.seq, mode: r.mode, from: cur, to: next,
        graceLastSeq: r.mode === 'normal' ? ev.seq + r.grace_events : ev.seq,
        graceUntilMs: r.grace_until === '' ? Infinity : Date.parse(r.grace_until)
      });
      cur = next;
      prev = ev;
    }
    return { gk, current: cur, rotations, retired };
  }
  function signersFor(sched, seq, ts) {
    let rot = null;
    for (const r of sched.rotations) if (r.seq < seq) rot = r;
    if (!rot) return { current: sched.gk, grace: null };
    const inGrace = rot.mode === 'normal' && seq <= rot.graceLastSeq && Date.parse(ts) <= rot.graceUntilMs;
    return { current: rot.to, grace: inGrace ? rot.from : null };
  }

  // pin: fingerprint or base64 genesis key; null = unpinned (explicit opt-in).
  async function verify(feedText, sigText, pin) {
    if (!/^[A-Za-z0-9+/]{86}==$/.test(sigText.trim())) throw new Error('signature must be 64 bytes base64');
    if (!feedText.endsWith('\n')) feedText += '\n';
    const bytes = enc.encode(feedText);
    if (bytes.length > MAX_BYTES) throw new Error('feed larger than ' + MAX_BYTES + ' bytes');

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
    if (!feed || typeof feed !== 'object' || Object.keys(feed).sort().join() !== FEED_FIELDS.join()) throw new Error('feed fields must be exactly ' + FEED_FIELDS.join(','));
    if (feed.format !== FORMAT) throw new Error('unsupported format (expected ' + FORMAT + ')');
    const h = feed.head;
    if (!h || typeof h !== 'object' || Object.keys(h).sort().join() !== 'hash,seq' || !Number.isSafeInteger(h.seq) || h.seq < 0 || !RE_HEX.test(h.hash)) throw new Error('bad head');
    if (typeof feed.key_id !== 'string' || !/^[0-9a-f]{16}$/.test(feed.key_id)) throw new Error('bad key_id');
    if (!Array.isArray(feed.events) || feed.events.length > MAX_EVENTS) throw new Error('bad events');
    if (!Array.isArray(feed.key_log) || feed.key_log.length > MAX_ROTATIONS) throw new Error('bad key_log');
    const re = nd
      ? [canon(Object.fromEntries(Object.entries(feed).filter(([k]) => k !== 'events')))].concat(feed.events.map(canon)).join('\n') + '\n'
      : canon(feed) + '\n';
    if (re !== feedText) throw new Error('feed bytes are not canonical');

    checkGenesis(feed.genesis, feed.feed_id);
    const fp = await fingerprint(feed.genesis);
    let pinKind = 'unpinned';
    if (pin !== null) {
      const norm = normalizePin(pin);
      if (norm) {
        if (fp.slice(0, norm.length) !== norm) throw new Error('ANCHOR MISMATCH: this feed\'s anchor is ' + fpDisplay(fp) + ', not the pinned hf2:' + norm);
        pinKind = 'fingerprint';
      } else if (RE_KEY.test(pin.trim())) {
        if (pin.trim() !== feed.genesis.pubkey) throw new Error('ANCHOR MISMATCH: genesis key differs from the pinned public key');
        pinKind = 'genesis-pubkey';
      } else {
        throw new Error('pin must be an anchor fingerprint (hf2:... with at least 32 hex chars) or a base64 public key');
      }
    }

    const sched = await keySchedule(feed.genesis, feed.key_log);
    if (feed.key_id !== sched.current.id) throw new Error('key_id does not match the key history');
    if (!(await ver(sched.current, sigText.trim(), bytes))) throw new Error('detached signature does NOT verify with the current key');
    const logBySeq = new Map(feed.key_log.map((e) => [e.seq, e]));
    for (const e of feed.key_log) if (e.seq > feed.head.seq) throw new Error('key_log entry after head');

    let prev = null;
    const ids = new Set();
    for (const ev of feed.events) {
      checkEvent(ev);
      const c = canon(body(ev));
      if ((await sha256Hex(enc.encode(c))) !== ev.hash) throw new Error('event ' + ev.seq + ': hash mismatch (tampered)');
      const logged = logBySeq.get(ev.seq);
      if (ev.type === 'rotate') {
        if (!logged || logged.hash !== ev.hash || logged.sig !== ev.sig || logged.cosig !== ev.cosig) throw new Error('event ' + ev.seq + ': rotate event not recorded in key_log');
      } else {
        if (logged) throw new Error('event ' + ev.seq + ': key_log records a rotation here');
        const s = signersFor(sched, ev.seq, ev.ts);
        const sb = enc.encode('hive-feed/2:event:' + c);
        if (!(await ver(s.current, ev.sig, sb)) && !(s.grace && (await ver(s.grace, ev.sig, sb)))) {
          for (const k of sched.retired) if (await ver(k, ev.sig, sb)) throw new Error('event ' + ev.seq + ': signed by a retired key after its grace window');
          throw new Error('event ' + ev.seq + ': bad signature');
        }
      }
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
    if (!prev && feed.head.seq === 0 && feed.head.hash !== GENESIS) throw new Error('empty feed must have genesis head');
    if (feed.events.length) {
      for (const e of feed.key_log) if (e.seq >= feed.events[0].seq && !ids.has(e.id)) throw new Error('rotation ' + e.seq + ' missing from event window');
    }
    return { feed, fp, pinKind, rotations: sched.rotations };
  }

  function cell(tr, text, cls) {
    const td = document.createElement('td');
    td.textContent = String(text);
    if (cls) td.className = cls;
    tr.appendChild(td);
  }

  function setStatus(ok, msg) {
    const s = $('status');
    s.className = ok === 'warn' ? 'warnstatus' : ok ? 'ok' : 'bad';
    s.textContent = msg;
  }

  function render(res) {
    const feed = res.feed;
    const out = $('results');
    out.replaceChildren();
    const fpBox = document.createElement('p');
    fpBox.className = 'fingerprint';
    fpBox.textContent = 'Anchor fingerprint of this feed: ' + fpDisplay(res.fp) + '   (full: ' + res.fp + ')';
    out.appendChild(fpBox);
    if (res.rotations.length) {
      const p = document.createElement('p');
      p.textContent = 'Key history: ' + res.rotations.map((r) => 'seq ' + r.seq + ' ' + r.mode + ' ' + r.from.id + ' -> ' + r.to.id +
        (r.graceLastSeq > r.seq ? ' (old key allowed through seq ' + r.graceLastSeq + ')' : '')).join('; ');
      out.appendChild(p);
    }
    const trusted = new Set($('trusted').value.split(',').map((x) => x.trim()).filter(Boolean));
    const maxAge = Number($('maxage').value) || 0;
    const now = Date.now();
    const warnings = [];
    if (feed.events.length && feed.events[0].seq > 1) warnings.push('Window starts at seq ' + feed.events[0].seq + '; earlier history was pruned and is not verified here.');
    if (!trusted.size) warnings.push('No verified poster IDs entered: every event is shown as untrusted.');
    if (now - Date.parse(feed.updated) > 7 * 86400000) warnings.push('Feed "updated" is more than 7 days old (stale or frozen feed?).');
    if (res.pinKind === 'unpinned') warnings.unshift('UNPINNED: the anchor was not compared with an out-of-band value. Anyone could have made this feed. Compare ' + fpDisplay(res.fp) + ' with the operator\'s announcement.');
    if (res.pinKind === 'genesis-pubkey') warnings.unshift('Pinned by genesis public key only; pinning the anchor fingerprint also commits to the recovery key.');
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
      const unpinned = $('unpinned').checked;
      const pin = $('anchor').value.trim();
      if (!unpinned && !pin) throw new Error('no pinned anchor. Paste the anchor fingerprint the operator published out of band, or tick the unpinned box to inspect without trust.');
      const res = await verify($('feed').value, $('sig').value, unpinned ? null : pin);
      const feed = res.feed;
      const summary = 'feed ' + feed.feed_id + ', anchor ' + fpDisplay(res.fp) + ', key_id ' + feed.key_id + ', ' + res.rotations.length + ' rotation(s), head seq ' + feed.head.seq + ', ' + feed.events.length + ' events in window.';
      if (unpinned) setStatus('warn', 'UNPINNED (not trusted): signatures, key history and chain are self-consistent, but nothing ties this feed to the real publisher. ' + summary);
      else setStatus(true, 'VALID: ' + summary + ' Anchor matches the pin; key history, signatures, hashes and chain check out.');
      render(res);
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
    $('anchor').value = d.anchor;
    $('unpinned').checked = false;
    $('trusted').value = d.trusted.join(',');
    run();
  });
  $('tamper').addEventListener('click', () => {
    const d = window.HIVE_DEMO;
    if (!d) return;
    $('feed').value = d.feed.replace('U-GIGATRON', 'U-GIGATRAN');
    $('sig').value = d.sig;
    $('anchor').value = d.anchor;
    $('unpinned').checked = false;
    run();
  });
  $('wrongpin').addEventListener('click', () => {
    const d = window.HIVE_DEMO;
    if (!d) return;
    $('feed').value = d.feed;
    $('sig').value = d.sig;
    $('anchor').value = d.wrongAnchor;
    $('unpinned').checked = false;
    run();
  });
  window.__hiveVerify = verify; // exposed for the headless test harness only
})();
