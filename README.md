# hive-feed

A signed, pull-only event feed for bots. A publisher appends events (tasks,
speed pings, DAO votes, announcements, results) to a static JSON file, signs
it with Ed25519, and serves it from any static host. Bots poll it with ETags,
verify it against an **anchor fingerprint they pinned out of band**, follow
in-band key rotations from that anchor, and act only on new, fresh events from
poster IDs they already trust.

Version 0.2.0 (format `hive-feed/2`). New in 0.2: first-pull trust anchor
(fingerprint pinning, unpinned mode refused by default), in-band key rotation
with grace windows, and an optional pre-committed recovery key. v0.1 feeds
(`hive-feed/1`) are not readable by 0.2 and vice versa; both fail closed.

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

Each accepted event is printed as `{"untrusted_data":true,"event":{...}}` with
control and bidi characters escaped. Warnings and skipped events go to stderr.
Exit code 1 means verification failed and state was not changed.

Library use:

```js
import { verifyFeedDetailed, applyFeed, emptyState, pull } from './src/index.js';
const v = verifyFeedDetailed(bytes, sig, 'hf2:b794-7865-...');   // throws on any problem
// v.feed, v.fingerprintDisplay, v.keyId, v.rotations, v.warnings
const { accepted, skipped, warnings, keyChanges, state } =
  applyFeed(savedState ?? emptyState(), v.feed, { trustedPosters: ['U-GIGATRON'] });
// verifyFeed(bytes, sig, pin) returns just the feed.
// pin = null is refused (HIVE_UNPINNED) unless { allowUnpinned: true }.
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

## Tests

```sh
npm test                         # node --test, no dependencies
node scripts/make-demo.js        # regenerate docs/demo.js with a fresh throwaway key
node scripts/browser-check.mjs   # optional; needs puppeteer-core installed separately
```

The test suite (80 tests) covers tampering, reordering, replay, rollback,
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

`scripts/browser-check.mjs` (headless Chrome, optional) checks the web page:
no network requests, XSS payloads inert, demo (with one rotation) valid,
tampered demo and wrong pin rejected, missing pin refused, unpinned shown as a
warning, and the same verdicts as the Node code on 7 rotation/recovery feeds.

Test and demo keys are THROWAWAY keys generated at run time and never written
to the repo. No production publisher key exists in this repository.

CI config is in `ci/test.yml` (copy to `.github/workflows/` to enable; it was
not placed there because the publishing token lacked the `workflow` scope).

## Honest limits

* **No live Slack ingestion.** Nothing here reads Slack. Someone still has to
  turn Slack messages into `append` calls, and that bridge decides what
  `poster_id` means. Garbage in, signed garbage out.
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
* **No equivocation detection across bots (no peer history comparison).** Each
  bot detects forks and key-history rewrites against its own history only.
* **First pull still trusts the chain position it gets.** The anchor proves
  who published the feed, not that the window is the newest one.
* **No external clock or transparency log.** `grace_until` and event `ts` are
  publisher-asserted; the event count is the hard grace bound.
* **Not deployed to the swarm.** No bot in the Gigatron swarm uses this today.
* **Unverified by anyone else.** Single author, no external review or audit.
  Read SPEC.md and the tests before relying on it.

## License

MIT, see [LICENSE](LICENSE).
