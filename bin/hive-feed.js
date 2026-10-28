#!/usr/bin/env node
import { readFileSync, writeFileSync, renameSync, existsSync, chmodSync, openSync, closeSync, writeSync, statSync } from 'node:fs';
import { resolve, dirname, join } from 'node:path';
import {
  generateKeyPair, importPrivateKey, publicKeyFromPrivate, keyId, emptyFeed, appendEvent, rotateKey, recoverKey,
  serializeFeed, serializeFeedNdjson, signFeedBytes, verifyFeed, verifyFeedDetailed, applyFeed, emptyState, pull,
  safeDisplay, anchorFingerprint, formatFingerprint, parseAllowlist, parseSlackInput, bridgeSlack, emptyBridgeState,
  parseBridgeState, makeView, serializeView, parseView, comparePeers, VIEW_FORMAT
} from '../src/index.js';

const USAGE = `hive-feed: signed, pull-only event feed (hive-feed/2)

Publisher:
  hive-feed keygen  --out <path-outside-any-git-repo> [--pub-out <file>]
  hive-feed init    --feed <feed.json> --key <private.key> --feed-id <id>
                    [--recovery-pubkey <b64> | --recovery-pubkey-file <f>] [--ndjson]
  hive-feed append  --feed <feed.json> --key <private.key> --type <task|speed_ping|dao_vote|announcement|result>
                    --id <id> --channel <channel> --poster <poster_id> [--url <https-url>]
                    (--text <s> | --text-file <f> | --text-digest <hex>) [--no-text] [--feed-id <id>]
                    [--keep <n>] [--ndjson] [--anchor <fingerprint>]
  hive-feed rotate  --feed <feed.json> --key <current.key> --next-key <next.key> --id <id>
                    [--grace-events <n>] [--grace-until <ISO ts>] [--text <s>] [--poster <id>] [--channel <c>]
                    [--keep <n>] [--ndjson] [--anchor <fingerprint>]
  hive-feed recover --feed <feed.json> --recovery-key <offline.key> --next-key <next.key> --id <id>
                    [--next-recovery-pubkey <b64> | --next-recovery-pubkey-file <f>] [--text <s>] [--poster <id>]
                    [--channel <c>] [--keep <n>] [--ndjson] [--anchor <fingerprint>]
  hive-feed fingerprint --feed <feed.json> [--sig <feed.json.sig>]

Slack bridge (offline; you fetch Slack JSON yourself, no tokens, no network):
  hive-feed bridge-slack --feed <feed.json> --key <publisher.key> --allowlist <file> --channel <C...>
                    [--input <slack.json> | stdin] [--state <bridge-state.json>] [--permalink-base <https://x.slack.com>]
                    [--dry-run] [--keep <n>] [--ndjson] [--anchor <fingerprint>]
                    (trust = Slack user ID on the allowlist; display names are ignored)

Peer history comparison:
  hive-feed view    --feed <feed.json> [--sig <f>] --anchor <hf2:...> [--observer <label>] [--sign-key <bot.key>]
                    [--out <view.json>]
  hive-feed compare --anchor <hf2:...> --mine <view.json|feed.json> --peer <view.json|feed.json> [--peer ...]
                    (feed files are verified, sig at <file>.sig; exit 0 consistent/prefix, 3 fork,
                     4 different genesis, 5 undetermined)

Consumer (exactly one trust source is required):
  --anchor <hf2:...>        anchor fingerprint published out of band by the operator (recommended)
  --pubkey <b64> | --pubkey-file <f>   genesis public key (v0.1 style, weaker: no recovery commitment)
  --unpinned-tofu           trust whatever valid feed comes first (NOT recommended, loudly warned)

  hive-feed verify  --feed <feed.json> [--sig <feed.json.sig>] <trust source>
                    [--trusted <id,id,...> | --trusted-file <f>] [--max-age <sec>]
  hive-feed pull    --url <https://.../feed.json> [--sig-url <url>] [<trust source>]
                    --state <state.json> (--trusted <ids> | --trusted-file <f>)
                    [--max-bytes <n>] [--timeout-ms <n>] [--max-age <sec>] [--since-param <name>] [--allow-http]
                    [--save-feed <feed.json>]   (keeps the verified file + .sig, e.g. for 'view')
                    (pull reuses the anchor saved in --state when no trust source is given)

Event text is untrusted data. This tool never executes it; consumers must not either.
`;

const BOOL_FLAGS = new Set(['no-text', 'ndjson', 'allow-http', 'help', 'unpinned-tofu', 'dry-run']);
const MULTI_FLAGS = new Set(['peer']);
const UNPINNED_BANNER = '!!! WARNING: UNPINNED (--unpinned-tofu). The publisher anchor was NOT checked against an\n' +
  '!!! out-of-band value. Anyone who can serve this URL could have produced this feed. Compare the\n' +
  '!!! fingerprint below with the operator\'s announcement before trusting it.\n';

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const k = a.slice(2);
      if (BOOL_FLAGS.has(k)) out[k] = true;
      else {
        if (i + 1 >= argv.length) usageError('missing value for --' + k);
        if (MULTI_FLAGS.has(k)) (out[k] = out[k] || []).push(argv[++i]);
        else out[k] = argv[++i];
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

// Returns a pin string, or null for explicit unpinned mode. required=false
// lets pull fall back to the anchor saved in its state file.
function loadPin(args, required = true) {
  const sources = ['anchor', 'pubkey', 'pubkey-file', 'unpinned-tofu'].filter((k) => args[k] !== undefined);
  if (sources.length > 1) usageError('give only one of --anchor, --pubkey, --pubkey-file, --unpinned-tofu');
  if (args.anchor) return args.anchor.trim();
  if (args.pubkey) return args.pubkey.trim();
  if (args['pubkey-file']) return readFileSync(args['pubkey-file'], 'utf8').trim();
  if (args['unpinned-tofu']) {
    process.stderr.write(UNPINNED_BANNER);
    return null;
  }
  if (!required) return undefined;
  return usageError('refusing to verify without a trust anchor: pass --anchor <hf2:...> (from the operator, out of band), or --pubkey, or explicitly --unpinned-tofu');
}

function loadPrivate(path) {
  const st = statSync(path);
  if ((st.mode & 0o077) !== 0) process.stderr.write('warning: private key file ' + path + ' is readable by group/others; chmod 600 it\n');
  return importPrivateKey(readFileSync(path, 'utf8'));
}

function loadOptionalPub(args, name) {
  if (args[name]) return args[name].trim();
  if (args[name + '-file']) return readFileSync(args[name + '-file'], 'utf8').trim();
  return '';
}

// The publisher's own local file: verify against --anchor if given, else
// against its own genesis (the publisher created it; this is not a consumer).
function loadOwnFeed(feedPath, args) {
  return verifyFeed(readFileSync(feedPath), readFileSync(feedPath + '.sig', 'utf8'), args.anchor || null, { allowUnpinned: !args.anchor });
}

function writeFeed(feedPath, feed, signerPriv, args) {
  const bytes = args.ndjson ? serializeFeedNdjson(feed) : serializeFeed(feed);
  const sig = signFeedBytes(signerPriv, Buffer.from(bytes, 'utf8'));
  // Each file is replaced atomically. A reader racing between the two renames
  // sees a feed/signature mismatch and fails closed; it never accepts an
  // unsigned or partially written feed.
  atomicWrite(feedPath, bytes);
  atomicWrite(feedPath + '.sig', sig + '\n');
}

function printAnchor(feed) {
  const fp = anchorFingerprint(feed.genesis);
  process.stdout.write('anchor ' + formatFingerprint(fp) + '\nanchor_full ' + fp + '\n');
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

function cmdInit(args) {
  const feedPath = resolve(need(args, 'feed'));
  if (existsSync(feedPath)) usageError('feed already exists: ' + feedPath);
  const priv = loadPrivate(need(args, 'key'));
  const feed = emptyFeed(need(args, 'feed-id'), publicKeyFromPrivate(priv), new Date(), { recoveryPubkey: loadOptionalPub(args, 'recovery-pubkey') });
  writeFeed(feedPath, feed, priv, args);
  printAnchor(feed);
  process.stderr.write('Publish the anchor through a channel bots already trust (e.g. a Mothership #announcements post or a QR code).\n' +
    (feed.genesis.recovery_digest ? 'Recovery key committed: keep its private half OFFLINE.\n' : 'No recovery key committed: a stolen key cannot be recovered in-band.\n'));
}

function cmdFingerprint(args) {
  const feedPath = need(args, 'feed');
  const v = verifyFeedDetailed(readFileSync(feedPath), readFileSync(args.sig || feedPath + '.sig', 'utf8'), null, { allowUnpinned: true });
  printAnchor(v.feed);
  process.stdout.write('key_id ' + v.keyId + '\nrotations ' + v.rotations.length + '\n');
  process.stderr.write('This is the fingerprint of THIS file. It only means something when compared with a copy obtained out of band.\n');
}

function cmdRotate(args, recovery) {
  const feedPath = resolve(need(args, 'feed'));
  const feed = loadOwnFeed(feedPath, args);
  const nextPriv = loadPrivate(need(args, 'next-key'));
  const input = { id: need(args, 'id'), text: args.text, poster_id: args.poster, channel: args.channel };
  for (const k of Object.keys(input)) if (input[k] === undefined) delete input[k];
  const opts = { keep: args.keep ? Number(args.keep) : 0 };
  let next;
  if (recovery) {
    next = recoverKey(feed, loadPrivate(need(args, 'recovery-key')), nextPriv, { ...input, nextRecoveryPubkey: loadOptionalPub(args, 'next-recovery-pubkey') }, opts);
  } else {
    const graceEvents = args['grace-events'] ? Number(args['grace-events']) : 0;
    next = rotateKey(feed, loadPrivate(need(args, 'key')), nextPriv, { ...input, graceEvents, graceUntil: args['grace-until'] || '' }, opts);
  }
  writeFeed(feedPath, next, nextPriv, args);
  process.stdout.write((recovery ? 'recovered' : 'rotated') + ' at seq ' + next.head.seq + ': key_id ' + feed.key_id + ' -> ' + next.key_id + '\n');
  printAnchor(next);
  process.stderr.write('The anchor does not change. Sign everything from now on with the new key.\n');
}

function cmdAppend(args) {
  const feedPath = resolve(need(args, 'feed'));
  const priv = loadPrivate(need(args, 'key'));
  const pub = publicKeyFromPrivate(priv);
  let feed;
  let created = false;
  if (existsSync(feedPath)) {
    feed = loadOwnFeed(feedPath, args);
    if (keyId(pub) !== feed.key_id) usageError('--key is not the current publisher key ' + feed.key_id + ' (the CLI signs the file with the current key only)');
  } else {
    feed = emptyFeed(need(args, 'feed-id'), pub, new Date(), { recoveryPubkey: loadOptionalPub(args, 'recovery-pubkey') });
    created = true;
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
  writeFeed(feedPath, next, priv, args);
  process.stdout.write('appended seq ' + next.head.seq + ' hash ' + next.head.hash + '\n');
  if (created) printAnchor(next);
}

function printResult(res) {
  for (const w of res.warnings) process.stderr.write('warning: ' + safeDisplay(w) + '\n');
  for (const s of res.skipped) process.stderr.write('skipped seq ' + s.seq + ' id ' + safeDisplay(s.id) + ': ' + s.reason + '\n');
  for (const ev of res.accepted) process.stdout.write(safeJson({ untrusted_data: true, event: ev }) + '\n');
}

function cmdVerify(args) {
  const feedPath = need(args, 'feed');
  const sigPath = args.sig || feedPath + '.sig';
  const pin = loadPin(args);
  const v = verifyFeedDetailed(readFileSync(feedPath), readFileSync(sigPath, 'utf8'), pin, { allowUnpinned: pin === null });
  const feed = v.feed;
  for (const w of v.warnings) process.stderr.write('warning: ' + safeDisplay(w) + '\n');
  process.stderr.write((pin === null ? 'UNPINNED-OK' : 'OK') + ' feed ' + feed.feed_id + ' anchor ' + v.fingerprintDisplay + ' key_id ' + feed.key_id +
    ' rotations ' + v.rotations.length + ' head seq ' + feed.head.seq + ' (' + feed.events.length + ' events in window)\n');
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
  const pin = loadPin(args, !state.anchor);
  const res = await pull({
    url: need(args, 'url'),
    sigUrl: args['sig-url'],
    pin: pin || undefined,
    allowUnpinned: pin === null,
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
  process.stderr.write('anchor ' + res.fingerprintDisplay + ' key_id ' + res.state.key_id + '\n');
  printResult(res);
  if (args['save-feed']) {
    const out = resolve(args['save-feed']);
    atomicWrite(out, res.bytes);
    atomicWrite(out + '.sig', res.sig + '\n');
  }
  atomicWrite(statePath, JSON.stringify(res.state, null, 2) + '\n', 0o600);
  process.stderr.write('state saved: seq ' + res.state.seq + '\n');
}

function cmdBridgeSlack(args) {
  const feedPath = resolve(need(args, 'feed'));
  if (!existsSync(feedPath)) usageError('feed does not exist: ' + feedPath + ' (create it with init first)');
  const keyPath = resolve(need(args, 'key'));
  const root = findGitRoot(dirname(keyPath));
  if (root) usageError('refusing to use a private key inside a git work tree (' + root + '). Keep the publisher key outside any repo.');
  const allowlist = parseAllowlist(readFileSync(need(args, 'allowlist'), 'utf8'));
  if (allowlist.length === 0) usageError('allowlist is empty: nobody would be trusted');
  const channel = need(args, 'channel');
  const slack = parseSlackInput(readFileSync(args.input && args.input !== '-' ? args.input : 0));
  const statePath = args.state ? resolve(args.state) : null;
  const state = statePath && existsSync(statePath) ? parseBridgeState(readFileSync(statePath, 'utf8')) : emptyBridgeState();
  const priv = loadPrivate(keyPath);
  const feed = loadOwnFeed(feedPath, args);
  if (keyId(publicKeyFromPrivate(priv)) !== feed.key_id) usageError('--key is not the current publisher key ' + feed.key_id);
  const res = bridgeSlack(feed, priv, slack, {
    channel, allowlist, state, permalinkBase: args['permalink-base'], keep: args.keep ? Number(args.keep) : 0
  });
  if (!args['dry-run'] && res.appended.length) writeFeed(feedPath, res.feed, priv, args);
  if (!args['dry-run'] && statePath) atomicWrite(statePath, JSON.stringify(res.state, null, 2) + '\n', 0o600);
  process.stdout.write(safeJson({ dry_run: !!args['dry-run'], appended: res.appended, skipped: res.skipped }) + '\n');
  process.stderr.write((args['dry-run'] ? 'dry run: would append ' : 'appended ') + res.appended.length + ', skipped ' + res.skipped.length +
    (res.appended.length && !args['dry-run'] ? ', head seq ' + res.feed.head.seq : '') + '\n');
}

// A file is either a view summary or a feed (with <file>.sig next to it).
function loadViewOrFeed(path, pin, args) {
  const bytes = readFileSync(path);
  let probe = null;
  try {
    probe = JSON.parse(bytes.toString('utf8'));
  } catch {
    probe = null; // NDJSON feed
  }
  if (probe && probe.format === VIEW_FORMAT) {
    const { view, signed } = parseView(bytes);
    return { view, evidence: 'view-summary', signed };
  }
  const v = verifyFeedDetailed(bytes, readFileSync(path + '.sig', 'utf8'), pin, { allowUnpinned: pin === null });
  return { view: makeView(v.feed, { observer: args.observer }), evidence: 'signed-feed', signed: true };
}

function cmdView(args) {
  const feedPath = need(args, 'feed');
  const anchor = need(args, 'anchor');
  const v = verifyFeedDetailed(readFileSync(feedPath), readFileSync(args.sig || feedPath + '.sig', 'utf8'), anchor);
  const signingKey = args['sign-key'] ? loadPrivate(args['sign-key']) : undefined;
  const view = makeView(v.feed, { observer: args.observer || '', signingKey });
  const out = serializeView(view);
  if (args.out) atomicWrite(resolve(args.out), out);
  else process.stdout.write(out);
  process.stderr.write('view feed ' + view.feed_id + ' anchor ' + v.fingerprintDisplay + ' head seq ' + view.head.seq + ' window ' +
    view.window.from_seq + '..' + view.head.seq + (signingKey ? ' (signed by observer key)' : ' (unsigned, digest only)') + '\n');
}

function cmdCompare(args) {
  const anchor = need(args, 'anchor');
  const peersArg = args.peer || usageError('--peer is required (repeat it for several peers)');
  const mine = loadViewOrFeed(need(args, 'mine'), anchor, args);
  const peers = peersArg.map((p) => ({ name: p, ...loadViewOrFeed(p, null, args) }));
  const res = comparePeers(mine.view, peers, { pin: anchor, mineEvidence: mine.evidence });
  for (const r of res.results) {
    process.stdout.write(safeJson({
      peer: r.peer, evidence: r.evidence, verdict: r.verdict, behind: r.behind === 'a' ? 'mine' : r.behind === 'b' ? 'peer' : null,
      divergence_seq: r.divergence_seq, divergence_exact: r.divergence_exact, proven_by_signatures: r.proven, detail: r.detail
    }) + '\n');
  }
  process.stderr.write('overall ' + res.overall + '\n');
  if (res.overall === 'fork') process.stderr.write('FORK: the feed showed different histories. ' +
    (res.results.some((r) => r.proven) ? 'Both sides are publisher-signed feeds: this is evidence of equivocation or key theft.' : 'At least one side is a peer claim (view summary), not proof.') + '\n');
  process.exitCode = { consistent: 0, fork: 3, different_genesis: 4, undetermined: 5 }[res.overall];
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
    case 'init': return cmdInit(args);
    case 'append': return cmdAppend(args);
    case 'rotate': return cmdRotate(args, false);
    case 'recover': return cmdRotate(args, true);
    case 'fingerprint': return cmdFingerprint(args);
    case 'verify': return cmdVerify(args);
    case 'pull': return cmdPull(args);
    case 'bridge-slack': return cmdBridgeSlack(args);
    case 'view': return cmdView(args);
    case 'compare': return cmdCompare(args);
    default: return usageError('unknown command ' + safeDisplay(cmd));
  }
}

main().catch((e) => {
  process.stderr.write('FAIL' + (e.code ? ' [' + e.code + ']' : '') + ': ' + safeDisplay(e.message) + '\n');
  process.exit(1);
});
