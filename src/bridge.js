// Offline Slack -> hive-feed bridge.
//
// Input: Slack message JSON the operator already fetched (a Slack export day
// file = array of messages, or a conversations.history-shaped object
// { ok, messages: [...] }), plus a caller-supplied allowlist of Slack user IDs.
// Output: new feed events (task | speed_ping | dao_vote) appended with the
// operator's publisher key.
//
// Rules:
// * Trust is decided ONLY by message.user (the Slack user ID). Display names,
//   real names, usernames, bot_profile names and anything in the text are
//   ignored for trust; they are trivially spoofable.
// * There are no built-in trusted IDs. An empty allowlist trusts nobody.
// * Message text is untrusted DATA. It is copied into the event verbatim and
//   only matched against fixed regexes to pick an event type; it is never
//   executed, evaluated or used to choose a key, channel or poster.
// * Dedupe key is channel + Slack ts. Event id = "slack-<channel>-<ts>", so a
//   replayed export never appends the same message twice (checked against the
//   feed window and an optional bridge state of seen keys, which survives
//   pruning).
// * No network, no Slack tokens. Fetching from Slack is the operator's job.
import { appendEvent } from './feed.js';
import { MAX_TEXT_CHARS } from './event.js';

export const BRIDGE_LIMITS = Object.freeze({
  maxInputBytes: 8 * 1024 * 1024,
  maxMessages: 20000,
  maxSeenKeys: 50000
});

// Slack user IDs: U... or W... (Enterprise Grid), uppercase alphanumerics.
export const RE_SLACK_USER = /^[UW][A-Z0-9]{2,20}$/;
// Slack conversation IDs: C (public), G (private/group), D (DM).
export const RE_SLACK_CHANNEL = /^[CGD][A-Z0-9]{2,20}$/;
// Slack message ts: seconds "." microseconds.
export const RE_SLACK_TS = /^\d{1,12}\.\d{6}$/;
// Only plain user messages and thread broadcasts. Edits, deletes, joins,
// bot_message (username can be overridden by the poster), etc. are skipped.
export const ALLOWED_SUBTYPES = Object.freeze(['', 'thread_broadcast']);

// Default classifier: fixed, case-insensitive regexes, first match wins.
// Order matters: a speed ping that mentions a task is still a speed ping.
export const DEFAULT_RULES = Object.freeze([
  { type: 'speed_ping', re: /\bspeed[\s_-]?ping\b/i },
  { type: 'dao_vote', re: /\bDP-\d{1,6}\b|\b(?:dao\s+)?vote\b|\bproposal\b/i },
  { type: 'task', re: /\btask\b|\bMAZE-\d{1,6}\b|\bmission\b/i }
]);

function fail(msg, code = 'HIVE_BRIDGE_INPUT') {
  const err = new Error(msg);
  err.code = code;
  throw err;
}

// Allowlist: array of IDs, or text with one ID per line ("#" comments allowed,
// anything after the ID on the line is ignored, e.g. "U0CBX31KMS8 mothership").
// Throws on anything that is not a Slack user ID, so a display name typed into
// the allowlist by mistake is an error, not a silent no-op.
export function parseAllowlist(input) {
  const ids = [];
  if (Array.isArray(input)) {
    for (const x of input) ids.push(String(x).trim());
  } else {
    for (const line of String(input).split('\n')) {
      const s = line.replace(/#.*/, '').trim();
      if (s) ids.push(s.split(/\s+/)[0]);
    }
  }
  for (const id of ids) {
    if (!RE_SLACK_USER.test(id)) fail('allowlist: ' + JSON.stringify(id.slice(0, 80)) + ' is not a Slack user ID (U.../W...); display names are never accepted', 'HIVE_BRIDGE_ALLOWLIST');
  }
  return [...new Set(ids)];
}

// Parse the Slack payload. Accepts bytes/string/parsed value.
export function parseSlackInput(input, limits = {}) {
  const lim = { ...BRIDGE_LIMITS, ...limits };
  let value = input;
  if (Buffer.isBuffer(input) || typeof input === 'string') {
    const buf = Buffer.isBuffer(input) ? input : Buffer.from(input, 'utf8');
    if (buf.length > lim.maxInputBytes) fail('input: ' + buf.length + ' bytes exceeds limit ' + lim.maxInputBytes, 'HIVE_TOO_LARGE');
    let str;
    try {
      str = new TextDecoder('utf-8', { fatal: true }).decode(buf);
    } catch {
      fail('input: invalid UTF-8');
    }
    try {
      value = JSON.parse(str);
    } catch {
      fail('input: not valid JSON');
    }
  }
  let messages;
  let channel = '';
  if (Array.isArray(value)) messages = value;
  else if (value !== null && typeof value === 'object' && Array.isArray(value.messages)) {
    if (value.ok === false) fail('input: Slack payload has ok:false');
    messages = value.messages;
    if (typeof value.channel === 'string') channel = value.channel;
  } else fail('input: expected an array of messages or an object with a "messages" array');
  if (messages.length > lim.maxMessages) fail('input: more than ' + lim.maxMessages + ' messages', 'HIVE_TOO_LARGE');
  return { messages, channel };
}

export function slackTsToIso(ts) {
  const [sec, micro] = ts.split('.');
  const ms = Number(sec) * 1000 + Math.floor(Number(micro) / 1000);
  const d = new Date(ms);
  if (!Number.isFinite(d.getTime())) fail('ts out of range');
  return d.toISOString();
}

export function dedupeKey(channel, ts) {
  return channel + ':' + ts;
}

export function eventIdFor(channel, ts) {
  return 'slack-' + channel + '-' + ts;
}

export function classify(text, rules = DEFAULT_RULES) {
  for (const r of rules) if (r.re.test(text)) return r.type;
  return null;
}

export function emptyBridgeState() {
  return { format: 'hive-feed/bridge-state-1', seen: [] };
}

function permalink(base, channel, ts) {
  if (!base) return '';
  const u = new URL(base);
  if (u.protocol !== 'https:' || u.username || u.password) fail('permalinkBase must be an https URL without credentials', 'HIVE_BRIDGE_CONFIG');
  return u.origin + '/archives/' + channel + '/p' + ts.replace('.', '');
}

// Decide what to do with each message. Pure: no keys, no I/O.
// opts: { channel, allowlist (array of user IDs), feed (for window dedupe),
//         state (bridge state), rules, permalinkBase }
// Returns { candidates: [{ key, input }], skipped: [{ index, key, reason }] }.
export function planBridge(slack, opts) {
  const channel = opts.channel;
  if (typeof channel !== 'string' || !RE_SLACK_CHANNEL.test(channel)) fail('channel: must be a Slack channel ID (C.../G.../D...)', 'HIVE_BRIDGE_CONFIG');
  if (slack.channel && slack.channel !== channel) fail('input is for channel ' + JSON.stringify(slack.channel.slice(0, 40)) + ', not ' + channel, 'HIVE_BRIDGE_CONFIG');
  const allow = new Set(parseAllowlist(opts.allowlist || []));
  const rules = opts.rules || DEFAULT_RULES;
  const seen = new Set((opts.state && opts.state.seen) || []);
  const windowIds = new Set(((opts.feed && opts.feed.events) || []).map((e) => e.id));
  const candidates = [];
  const skipped = [];
  const batch = new Set();
  slack.messages.forEach((m, index) => {
    const skip = (reason, key = null) => skipped.push({ index, key, reason });
    if (m === null || typeof m !== 'object' || Array.isArray(m)) return skip('malformed: message is not an object');
    if (typeof m.ts !== 'string' || !RE_SLACK_TS.test(m.ts)) return skip('malformed: missing or invalid ts');
    if (m.channel !== undefined && m.channel !== channel) return skip('malformed: message.channel does not match the bridge channel');
    const key = dedupeKey(channel, m.ts);
    if (m.type !== undefined && m.type !== 'message') return skip('not a message', key);
    const subtype = m.subtype === undefined ? '' : m.subtype;
    if (!ALLOWED_SUBTYPES.includes(subtype)) return skip('subtype not accepted: ' + String(subtype).slice(0, 40), key);
    if (typeof m.user !== 'string' || !RE_SLACK_USER.test(m.user)) return skip('malformed: missing or invalid user ID', key);
    if (!allow.has(m.user)) return skip('sender not on allowlist (matched by user ID only)', key);
    if (typeof m.text !== 'string') return skip('malformed: text is not a string', key);
    if (m.text.length > MAX_TEXT_CHARS) return skip('text longer than ' + MAX_TEXT_CHARS + ' chars', key);
    const id = eventIdFor(channel, m.ts);
    if (seen.has(key) || windowIds.has(id)) return skip('duplicate: already appended', key);
    if (batch.has(key)) return skip('duplicate: repeated in this input', key);
    const type = classify(m.text, rules);
    if (!type) return skip('not recognized as task, speed ping or vote', key);
    batch.add(key);
    candidates.push({
      index,
      key,
      slackTs: m.ts,
      input: {
        type, id, channel, poster_id: m.user, url: permalink(opts.permalinkBase, channel, m.ts), text: m.text,
        ts: slackTsToIso(m.ts)
      }
    });
  });
  // Feed ts must not go backwards: append in Slack order.
  candidates.sort((a, b) => cmpSlackTs(a.slackTs, b.slackTs));
  return { candidates, skipped };
}

function cmpSlackTs(a, b) {
  const [as, au] = a.split('.');
  const [bs, bu] = b.split('.');
  return Number(as) - Number(bs) || Number(au) - Number(bu);
}

// Plan and append. privateKey is the operator's current publisher key.
// Event ts is the Slack message time, clamped forward to the feed's last
// event ts if needed (feed ts is non-decreasing); the original Slack ts is
// always recoverable from the event id.
// Returns { feed, appended: [{ key, id, type, seq }], skipped, state }.
export function bridgeSlack(feed, privateKey, slack, opts = {}) {
  const now = opts.now || new Date();
  const { candidates, skipped } = planBridge(slack, { ...opts, feed });
  let cur = feed;
  const appended = [];
  const seen = [...((opts.state && opts.state.seen) || [])];
  for (const c of candidates) {
    const last = cur.events[cur.events.length - 1];
    const input = { ...c.input };
    if (last && Date.parse(input.ts) < Date.parse(last.ts)) input.ts = last.ts;
    if (Date.parse(input.ts) > now.getTime() + 300000) {
      skipped.push({ index: c.index, key: c.key, reason: 'Slack ts more than 5 minutes in the future' });
      continue;
    }
    cur = appendEvent(cur, privateKey, input, { now, keep: opts.keep || 0 });
    appended.push({ key: c.key, id: input.id, type: input.type, seq: cur.head.seq });
    seen.push(c.key);
  }
  const lim = { ...BRIDGE_LIMITS, ...(opts.limits || {}) };
  return {
    feed: cur,
    appended,
    skipped,
    state: { format: 'hive-feed/bridge-state-1', seen: [...new Set(seen)].slice(-lim.maxSeenKeys) }
  };
}

export function parseBridgeState(text) {
  let s;
  try {
    s = JSON.parse(text);
  } catch {
    fail('bridge state: not valid JSON', 'HIVE_BRIDGE_STATE');
  }
  if (!s || s.format !== 'hive-feed/bridge-state-1' || !Array.isArray(s.seen) || !s.seen.every((k) => typeof k === 'string')) {
    fail('bridge state: unexpected format', 'HIVE_BRIDGE_STATE');
  }
  return s;
}
