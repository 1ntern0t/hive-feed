#!/usr/bin/env node
import { readFileSync, writeFileSync, renameSync, existsSync, chmodSync, openSync, closeSync, writeSync, statSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import {
  generateKeyPair, importPrivateKey, publicKeyFromPrivate, keyId, emptyFeed, appendEvent,
  serializeFeed, serializeFeedNdjson, signFeedBytes, verifyFeed, applyFeed, emptyState, pull, safeDisplay
} from '../src/index.js';

const USAGE = `hive-feed: signed, pull-only event feed (hive-feed/1)

  hive-feed keygen --out <path-outside-any-git-repo> [--pub-out <file>]
  hive-feed append --feed <feed.json> --key <private.key> --type <task|speed_ping|dao_vote|announcement|result>
                   --id <id> --channel <channel> --poster <poster_id> [--url <https-url>]
                   (--text <s> | --text-file <f> | --text-digest <hex>) [--no-text] [--feed-id <id>]
                   [--keep <n>] [--ndjson]
  hive-feed verify --feed <feed.json> [--sig <feed.json.sig>] (--pubkey <b64> | --pubkey-file <f>)
                   [--trusted <id,id,...> | --trusted-file <f>] [--max-age <sec>]
  hive-feed pull   --url <https://.../feed.json> [--sig-url <url>] (--pubkey <b64> | --pubkey-file <f>)
                   --state <state.json> (--trusted <ids> | --trusted-file <f>)
                   [--max-bytes <n>] [--timeout-ms <n>] [--max-age <sec>] [--since-param <name>] [--allow-http]

Event text is untrusted data. This tool never executes it; consumers must not either.
`;

const BOOL_FLAGS = new Set(['no-text', 'ndjson', 'allow-http', 'help']);

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      if (BOOL_FLAGS.has(k)) out[k] = true;
      else {
        if (i + 1 >= argv.length) usageError('missing value for --' + k);
        out[k] = argv[++i];
      }
    } else out._.push(a);
  }
  return out;
}

function usageError(msg) {
  process.stderr.write('error: ' + msg + '\n\n' + USAGE);
  process.exit(2);
}

function need(args, k) {
  if (args[k] === undefined) usageError('--' + k + ' is required');
  return args[k];
}

function findGitRoot(p) {
  let d = p;
  for (;;) {
    if (existsSync(join(d, '.git'))) return d;
    const up = dirname(d);
    if (up === d) return null;
    d = up;
  }
}

function atomicWrite(path, data, mode = 0o644) {
  const tmp = path + '.tmp-' + process.pid;
  writeFileSync(tmp, data, { mode });
  renameSync(tmp, path);
}

// JSON output with C1 controls and bidi/zero-width chars also escaped.
function safeJson(obj) {
  return JSON.stringify(obj).replace(/[\u007f-\u009f\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029\ufeff]/g,
    (c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'));
}

function loadPubkey(args) {
  if (args.pubkey) return args.pubkey.trim();
  if (args['pubkey-file']) return readFileSync(args['pubkey-file'], 'utf8').trim();
  return usageError('--pubkey or --pubkey-file is required');
}

function loadTrusted(args) {
  if (args.trusted) return args.trusted.split(',').map((s) => s.trim()).filter(Boolean);
  if (args['trusted-file']) {
    return readFileSync(args['trusted-file'], 'utf8').split('\n').map((s) => s.replace(/#.*/, '').trim()).filter(Boolean);
  }
  return null;
}

function cmdKeygen(args) {
  const out = resolve(need(args, 'out'));
  const root = findGitRoot(dirname(out));
  if (root) usageError('refusing to write a private key inside a git work tree (' + root + '). Choose a path outside any repo.');
  const { publicKey, privateKeyPem } = generateKeyPair();
  const fd = openSync(out, 'wx', 0o600);
  try {
    writeSync(fd, privateKeyPem);
  } finally {
    closeSync(fd);
  }
  chmodSync(out, 0o600);
  if (args['pub-out']) writeFileSync(args['pub-out'], publicKey + '\n');
  process.stdout.write('public_key ' + publicKey + '\nkey_id ' + keyId(publicKey) + '\n');
}

function cmdAppend(args) {
  const feedPath = resolve(need(args, 'feed'));
  const keyPath = need(args, 'key');
  const st = statSync(keyPath);
  if ((st.mode & 0o077) !== 0) process.stderr.write('warning: private key file is readable by group/others; chmod 600 it\n');
  const priv = importPrivateKey(readFileSync(keyPath, 'utf8'));
  const pub = publicKeyFromPrivate(priv);
  let feed;
  if (existsSync(feedPath)) {
    feed = verifyFeed(readFileSync(feedPath), readFileSync(feedPath + '.sig', 'utf8'), pub);
  } else {
    feed = emptyFeed(need(args, 'feed-id'), pub);
  }
  let text;
  if (args.text !== undefined) text = args.text;
  else if (args['text-file']) text = readFileSync(args['text-file'], 'utf8');
  const input = {
    type: need(args, 'type'),
    id: need(args, 'id'),
    channel: need(args, 'channel'),
    poster_id: need(args, 'poster'),
    url: args.url || '',
    text,
    text_digest: args['text-digest']
  };
  if (text === undefined && !input.text_digest) usageError('one of --text, --text-file, --text-digest is required');
  const next = appendEvent(feed, priv, input, { includeText: !args['no-text'], keep: args.keep ? Number(args.keep) : 0 });
  const bytes = args.ndjson ? serializeFeedNdjson(next) : serializeFeed(next);
  const sig = signFeedBytes(priv, Buffer.from(bytes, 'utf8'));
  // Each file is replaced atomically. A reader racing between the two renames
  // sees a feed/signature mismatch and fails closed; it never accepts an
  // unsigned or partially written feed.
  atomicWrite(feedPath, bytes);
  atomicWrite(feedPath + '.sig', sig + '\n');
  process.stdout.write('appended seq ' + next.head.seq + ' hash ' + next.head.hash + '\n');
}

function printResult(res) {
  for (const w of res.warnings) process.stderr.write('warning: ' + safeDisplay(w) + '\n');
  for (const s of res.skipped) process.stderr.write('skipped seq ' + s.seq + ' id ' + safeDisplay(s.id) + ': ' + s.reason + '\n');
  for (const ev of res.accepted) process.stdout.write(safeJson({ untrusted_data: true, event: ev }) + '\n');
}

function cmdVerify(args) {
  const feedPath = need(args, 'feed');
  const sigPath = args.sig || feedPath + '.sig';
  const pub = loadPubkey(args);
  const feed = verifyFeed(readFileSync(feedPath), readFileSync(sigPath, 'utf8'), pub);
  process.stderr.write('OK feed ' + feed.feed_id + ' key_id ' + feed.key_id + ' head seq ' + feed.head.seq + ' (' + feed.events.length + ' events in window)\n');
  const trusted = loadTrusted(args);
  if (trusted) {
    const policy = { trustedPosters: trusted };
    if (args['max-age']) policy.maxAgeSec = Number(args['max-age']);
    printResult(applyFeed(emptyState(), feed, policy));
  }
}

async function cmdPull(args) {
  const statePath = resolve(need(args, 'state'));
  const trusted = loadTrusted(args);
  if (!trusted) usageError('--trusted or --trusted-file is required for pull (only verified poster IDs are trusted)');
  const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : emptyState();
  const policy = { trustedPosters: trusted };
  if (args['max-age']) policy.maxAgeSec = Number(args['max-age']);
  const res = await pull({
    url: need(args, 'url'),
    sigUrl: args['sig-url'],
    publicKey: loadPubkey(args),
    state,
    policy,
    maxBytes: args['max-bytes'] ? Number(args['max-bytes']) : undefined,
    timeoutMs: args['timeout-ms'] ? Number(args['timeout-ms']) : undefined,
    sinceParam: args['since-param'],
    allowHttp: !!args['allow-http']
  });
  if (!res.changed) {
    process.stderr.write('not modified (seq ' + state.seq + ')\n');
    return;
  }
  printResult(res);
  atomicWrite(statePath, JSON.stringify(res.state, null, 2) + '\n', 0o600);
  process.stderr.write('state saved: seq ' + res.state.seq + '\n');
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];
  if (!cmd || args.help) {
    process.stdout.write(USAGE);
    return;
  }
  switch (cmd) {
    case 'keygen': return cmdKeygen(args);
    case 'append': return cmdAppend(args);
    case 'verify': return cmdVerify(args);
    case 'pull': return cmdPull(args);
    default: return usageError('unknown command ' + safeDisplay(cmd));
  }
}

main().catch((e) => {
  process.stderr.write('FAIL' + (e.code ? ' [' + e.code + ']' : '') + ': ' + safeDisplay(e.message) + '\n');
  process.exit(1);
});
