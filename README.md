# hive-feed

A signed, pull-only event feed for bots. A publisher appends events (tasks,
speed pings, DAO votes, announcements, results) to a static JSON file, signs
it with Ed25519, and serves it from any static host. Bots poll it with ETags,
verify it against an **anchor fingerprint they pinned out of band**, follow
in-band key rotations from that anchor, and act only on new, fresh events from
poster IDs they already trust.

Version 0.3.0 (feed format still `hive-feed/2`, so 0.2 feeds verify unchanged).
New in 0.3:

* **Review packet** for outside reviewers: [docs/REVIEW.md](docs/REVIEW.md).
  **The cryptography is unreviewed.** Nobody but the author has checked it.
* **Offline Slack -> feed bridge** (`hive-feed bridge-slack`): turns Slack
  message JSON you already fetched into signed task / speed ping / vote
  events. Only senders whose Slack **user ID** is on your allowlist count;
  display names are ignored. Replays are deduped by channel + ts. No network,
  no Slack tokens.
* **Peer history compare** (`hive-feed view`, `hive-feed compare`): bots
  exchange a small hashed (optionally signed) view summary or the signed feed
  file itself and learn whether they saw the same history, one is behind, or
  the publisher showed them a fork (with the earliest differing seq).
* Fix: CLI `pull` without `--timeout-ms` / `--max-bytes` failed in 0.2.0
  (undefined flags overrode the defaults). `pull --save-feed` keeps the
  verified file for `view`/`compare`.

New in 0.2: first-pull trust anchor (fingerprint pinning, unpinned mode
refused by default), in-band key rotation with grace windows, and an optional
pre-committed recovery key. v0.1 feeds (`hive-feed/1`) are not readable by
0.2+ and vice versa; both fail closed.

> **Status notes.** GitHub Actions has **not** run on this repository: the
> workflow file lives in [`ci/test.yml`](ci/test.yml) because the token used to
> publish lacked the `workflow` scope, so it is not in `.github/workflows/`.
> Tests were run locally only. **Publisher keys stay with whoever runs the feed
> (Mothership)**, never with xirionmeta or this repository. No real key exists
> here; tests use throwaway keys generated at run time, and the bridge never
> generates keys (the operator passes the path to their own key).

No webhooks. No inbound ports. No shared secrets. Zero dependencies (Node 20+,
`node:crypto`).

Built as a pitch for the Gigatron swarm build challenge "Unify the Network".

* Format and threat model: [SPEC.md](SPEC.md)
* Security notes: [SECURITY.md](SECURITY.md)
* In-browser verifier (no network): `docs/index.html`, published at
  https://1ntern0t.github.io/hive-feed/ once GitHub Pages is enabled

## Why pull + sign

Webhooks need every bot to expose an endpoint and every publisher to hold a
list of secrets. A signed static file inverts that: the publisher holds one
private key, everyone else holds one public key, and any dumb host (or mirror,
or cache) can serve the bytes because it cannot forge them.

## Quick start

```sh
# 1. Publisher: make keys OUTSIDE any git repo (the CLI refuses otherwise).
#    The recovery key is optional but strongly recommended; keep it OFFLINE.
node bin/hive-feed.js keygen --out ~/.config/hive-feed/publisher.key
node bin/hive-feed.js keygen --out /media/offline-usb/recovery.key   # prints its public_key

# 2. Publisher: create the feed. Prints the ANCHOR fingerprint, e.g.
#    anchor hf2:b794-7865-d87b-b571-7b31-94de-2c9a-2d38
#    Post it where bots already trust you (Mothership #announcements, a QR code).
node bin/hive-feed.js init --feed site/feed.json --key ~/.config/hive-feed/publisher.key \
  --feed-id gigatron-main --recovery-pubkey <recovery public_key>

# 3. Publisher: append events. Writes feed.json and feed.json.sig atomically.
node bin/hive-feed.js append --feed site/feed.json --key ~/.config/hive-feed/publisher.key \
  --type task --id task-42 --channel build-challenge \
  --poster U-GIGATRON --url https://example.org/task/42 --text "Unify the Network"

# 4. Anyone: verify a local copy against the announced anchor.
node bin/hive-feed.js verify --feed site/feed.json --anchor hf2:b794-7865-... --trusted U-GIGATRON

# 5. Bot: poll. Prints accepted events as NDJSON, keeps state (incl. the anchor) between runs.
node bin/hive-feed.js pull --url https://you.github.io/feed/feed.json \
  --anchor hf2:b794-7865-... --state ~/.local/state/hive-feed.json --trusted U-GIGATRON
```

`pull` fetches the signature from the feed URL with `.sig` appended to the path
(`feed.json?v=3` becomes `feed.json.sig?v=3`). Pass `--sig-url` to use a different location.

Without `--anchor` (or `--pubkey`), `verify` and a first `pull` refuse to run.
`--unpinned-tofu` exists for inspection and prints a loud warning with the
fingerprint to compare by hand.

Key rotation and recovery:

```sh
# Planned rotation: signed by the current key, countersigned by the next key.
# The old key may sign at most 5 more events, and none after the deadline.
node bin/hive-feed.js keygen --out ~/.config/hive-feed/publisher-2.key
node bin/hive-feed.js rotate --feed site/feed.json --key ~/.config/hive-feed/publisher.key \
  --next-key ~/.config/hive-feed/publisher-2.key --id rotate-2026-11 \
  --grace-events 5 --grace-until 2026-11-02T00:00:00Z

# Current key stolen or lost: force-rotate with the offline recovery key
# (single use; commit a fresh recovery key at the same time).
node bin/hive-feed.js recover --feed site/feed.json --recovery-key /media/offline-usb/recovery.key \
  --next-key ~/.config/hive-feed/publisher-3.key --id recover-1 --next-recovery-pubkey <new recovery public_key>
```

The anchor never changes; bots keep their pin and follow the key history.

Slack bridge (offline). You fetch the Slack JSON yourself (a Slack export day
file, or the body of a `conversations.history` call you made with your own
token); the bridge never talks to Slack:

```sh
# allowlist: one Slack user ID per line; see examples/slack-allowlist.example.txt
cp examples/slack-allowlist.example.txt ~/.config/hive-feed/allowlist.txt   # then check every ID
node bin/hive-feed.js bridge-slack --feed site/feed.json --key ~/.config/hive-feed/publisher.key \
  --allowlist ~/.config/hive-feed/allowlist.txt --channel C0123ABCD \
  --state ~/.local/state/hive-bridge.json --input history.json        # or pipe JSON on stdin
# --dry-run shows what would be appended; --permalink-base https://<workspace>.slack.com adds links
```

It prints a JSON report (`appended`, `skipped` with reasons) and appends
`task` / `speed_ping` / `dao_vote` events with `poster_id` = Slack user ID and
`id` = `slack-<channel>-<ts>`. Consumers then use the same IDs:
`--trusted U0CBX31KMS8,...`. Matching rules are in SPEC.md "Slack bridge".

Peer history compare:

```sh
# Keep the verified file when pulling, then describe it.
node bin/hive-feed.js pull --url https://.../feed.json --anchor hf2:... --state s.json --trusted U0CBX31KMS8 --save-feed mine.json
node bin/hive-feed.js view --feed mine.json --anchor hf2:... --observer my-bot --out my.view.json   # [--sign-key bot.key]
# Compare with peers' view summaries or their saved signed feed files.
node bin/hive-feed.js compare --anchor hf2:... --mine mine.json --peer peer1.view.json --peer peer2-feed.json
# exit 0 consistent/prefix, 3 fork, 4 different genesis, 5 undetermined
```

Each accepted event is printed as `{"untrusted_data":true,"event":{...}}` with
control and bidi characters escaped. Warnings and skipped events go to stderr.
Exit code 1 means verification failed and state was not changed.

Library use:

```js
import { verifyFeedDetailed, applyFeed, emptyState, pull, bridgeSlack, parseSlackInput, makeView, compareViews } from './src/index.js';
const v = verifyFeedDetailed(bytes, sig, 'hf2:b794-7865-...');   // throws on any problem
// v.feed, v.fingerprintDisplay, v.keyId, v.rotations, v.warnings
const { accepted, skipped, warnings, keyChanges, state } =
  applyFeed(savedState ?? emptyState(), v.feed, { trustedPosters: ['U-GIGATRON'] });
// verifyFeed(bytes, sig, pin) returns just the feed.
// pin = null is refused (HIVE_UNPINNED) unless { allowUnpinned: true }.
const b = bridgeSlack(feed, publisherPriv, parseSlackInput(slackJson), { channel: 'C0123ABCD', allowlist: ['U0CBX31KMS8'], state });
// b.feed, b.appended, b.skipped, b.state
const r = compareViews(makeView(v.feed), peerView);   // r.verdict, r.divergence_seq, r.divergence_exact
```

## What the checks cover

| Attack | Result |
| --- | --- |
| Edited byte anywhere | detached signature fails |
| Edited event, file re-signed | event hash / signature fails |
| Reordered, removed or inserted events | `seq` / `prev_hash` / `head` chain fails |
| Truncated file | signature or parse fails |
| Older valid feed served again (rollback) | rejected against stored `seq` |
| Different history at same `seq` (fork) | rejected against stored `hash` |
| Old event re-emitted under a new id or seq | seen-id set, max age |
| Unknown poster | skipped unless on your verified list |
| Oversized feed / slow host | size, count and timeout limits |
| Prompt / HTML / shell / ANSI injection in text | kept as inert data; never executed |
| Valid feed from someone else (first pull) | `HIVE_ANCHOR_MISMATCH` against the pinned fingerprint |
| No pin at all | refused (`HIVE_UNPINNED`) unless unpinned mode is explicitly chosen |
| Rotation not signed by the current key, or bad countersignature | `HIVE_BAD_ROTATION` |
| Rotation replayed / rotating back to a used key | `HIVE_ROTATION_REPLAY` |
| Old key signing after its grace window | `HIVE_KEY_RETIRED` |
| Recovery with a key that does not match the committed digest | `HIVE_BAD_ROTATION` |
| Key history rewritten since the bot last pulled | `HIVE_KEY_CHANGED` |
| Publisher shows two bots different histories | `compare` reports `fork` and the earliest differing seq (only if the bots compare) |
| Slack lookalike: right display name, wrong user ID | bridge skips it (`sender not on allowlist`) |
| Same Slack export bridged twice | bridge skips it (`duplicate: already appended`) |

## Tests

```sh
npm test                         # node --test, no dependencies
node scripts/make-demo.js        # regenerate docs/demo.js with a fresh throwaway key
node scripts/browser-check.mjs   # optional; needs puppeteer-core installed separately
```

The test suite (101 tests in 0.3.0; 81 before it) covers tampering, reordering, replay, rollback,
forks, truncated chains, oversized input, bad and wrong-key signatures,
non-canonical bytes, injection strings round-tripping inert through library
and CLI, and `pull` against a local HTTP server (ETag/304, size and time
limits, https-only). New in 0.2 (`test/anchor.test.js`,
`test/rotation.test.js`, `test/cli.test.js`): fingerprint match, mismatch,
look-alike genesis with a different recovery key, too-short pins, unpinned
refusal and explicit opt-in, saved anchor pinning later pulls; valid rotation
(anchor unchanged, consumer state follows, pruned window), bad-signature and
bad-countersignature rotations, edited rotations, old key rotating during
grace, rotate events missing from `key_log`, rotation replays, key-history
rewrite detected by a consumer, old-key events after the grace count and after
`grace_until`, recovery after theft (and after a thief's own rotation),
recovery with a wrong key, a wrong signer, or no committed key, normal
rotations unable to touch the recovery key; CLI `init`/`fingerprint`/`rotate`/
`recover` and trust-source handling.
New in 0.3 (`test/bridge.test.js`, `test/compare.test.js`): bridge accepts
allowlisted task / speed ping / vote messages and signs them; rejects senders
not on the allowlist, lookalike display names / usernames / bot profiles /
quoted IDs with the wrong user ID, `bot_message` and edit subtypes, display
names in the allowlist, an empty allowlist, malformed payloads (bad JSON,
bad UTF-8, `ok:false`, wrong shape, missing or bad ts/user/text, oversized
text, channel mismatch, size limits); dedupes replays via the feed window, the
bridge state (also after pruning) and within one input; keeps injection text
inert; orders and clamps timestamps; CLI with the example files, stdin and
`--dry-run`. Compare: equal, prefix (both directions, empty feed, pruned
longer view), fork (exact index, same length, at seq 1, shorter head not in
longer), fork with pruned windows (upper bound), non-overlapping windows
(undetermined), different genesis with the same feed_id, key-history fork via
competing rotations, view digest / signature / shape / canonical checks,
fabricated views, `comparePeers` pin check and proof flag, CLI `view` /
`compare` exit codes, and CLI `pull --save-feed` against a local server.

`scripts/browser-check.mjs` (headless Chrome, optional) checks the web page:
no network requests, XSS payloads inert, demo (with one rotation) valid,
tampered demo and wrong pin rejected, missing pin refused, unpinned shown as a
warning, and the same verdicts as the Node code on 7 rotation/recovery feeds.

Test and demo keys are THROWAWAY keys generated at run time and never written
to the repo. No production publisher key exists in this repository.

CI config is in `ci/test.yml` (copy to `.github/workflows/` to enable; it was
not placed there because the publishing token lacked the `workflow` scope).

## Honest limits

* **The cryptography is unreviewed.** See [docs/REVIEW.md](docs/REVIEW.md);
  please do not treat it as production-ready until someone outside has read it.
* **The Slack bridge is offline and only as good as its input.** It does not
  fetch from Slack (no tokens, no network); the operator must. It cannot tell
  a real Slack export from a forged JSON file, and Slack history carries no
  signatures. Trust is the allowlist of user IDs, which the operator must
  check by hand. Type detection is keyword regexes, so a trusted sender's
  chit-chat containing "task" or "vote" becomes an event. Without the bridge
  state file, messages already pruned from the feed window can be appended
  again. Edits and deletes in Slack are ignored, not propagated.
* **The anchor is only as good as the channel it was announced on.** If the
  operator's announcement account is spoofed or the bot copies the
  fingerprint from the feed host, pinning protects nothing. No QR generator is
  included; any QR tool can encode the `hf2:` string.
* **Publisher key custody is still the hard problem.** Whoever holds the
  current key can publish anything until a recovery rotation is published.
  In-band rotation cannot recover from a stolen key by itself (the thief can
  sign rotations too); only the optional offline recovery key can, and only if
  it was committed in genesis. Recovery does not undo events the thief already
  published, and a stolen recovery key is a full takeover.
* **Fresh bots can be rolled back across a rotation.** Someone holding a
  retired key can serve a bot with no saved state an older, validly signed
  history from before the rotation. Bots with state reject it.
* **No revocation list and no threshold keys.** One key signs at a time.
* **Freeze attacks are only warned about.** A host can keep serving the last
  valid file; consumers see a staleness warning, not an error, unless they turn
  on strict freshness.
* **Peer comparison is a tool, not a network.** Bots must exchange views or
  feed files themselves; nothing here gossips them, and no swarm bot does it
  today. A peer's view summary is a claim (a liar can invent or hide a fork);
  only two signed feed files are proof. Heavily pruned windows can make the
  answer `undetermined` or give only an upper bound on the divergence point.
* **First pull still trusts the chain position it gets.** The anchor proves
  who published the feed, not that the window is the newest one.
* **No external clock or transparency log.** `grace_until` and event `ts` are
  publisher-asserted; the event count is the hard grace bound.
* **Not deployed to the swarm.** No bot in the Gigatron swarm uses this today.
* **CI has not run.** GitHub Actions is not enabled (workflow in `ci/`, see
  the status note above); all test results are from local runs.
* **Unverified by anyone else.** Single author, no external review or audit.
  Read SPEC.md, docs/REVIEW.md and the tests before relying on it.

## License

MIT, see [LICENSE](LICENSE).
