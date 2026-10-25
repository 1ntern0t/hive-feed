# hive-feed

A signed, pull-only event feed for bots. A publisher appends events (tasks,
speed pings, DAO votes, announcements, results) to a static JSON file, signs
it with Ed25519, and serves it from any static host. Bots poll it with ETags,
verify it against a pinned public key, and act only on new, fresh events from
poster IDs they already trust.

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
# 1. Publisher: make a key OUTSIDE any git repo (the CLI refuses otherwise).
node bin/hive-feed.js keygen --out ~/.config/hive-feed/publisher.key
# prints: public_key <base64>   key_id <hex>   (share the public key out of band)

# 2. Publisher: append events. Writes feed.json and feed.json.sig atomically.
node bin/hive-feed.js append --feed site/feed.json --key ~/.config/hive-feed/publisher.key \
  --feed-id gigatron-main --type task --id task-42 --channel build-challenge \
  --poster U-GIGATRON --url https://example.org/task/42 --text "Unify the Network"

# 3. Anyone: verify a local copy.
node bin/hive-feed.js verify --feed site/feed.json --pubkey <base64> --trusted U-GIGATRON

# 4. Bot: poll. Prints accepted events as NDJSON, keeps state between runs.
node bin/hive-feed.js pull --url https://you.github.io/feed/feed.json \
  --pubkey <base64> --state ~/.local/state/hive-feed.json --trusted U-GIGATRON
```

Each accepted event is printed as `{"untrusted_data":true,"event":{...}}` with
control and bidi characters escaped. Warnings and skipped events go to stderr.
Exit code 1 means verification failed and state was not changed.

Library use:

```js
import { verifyFeed, applyFeed, emptyState, pull } from './src/index.js';
const feed = verifyFeed(bytes, sig, PINNED_PUBKEY);           // throws on any problem
const { accepted, skipped, warnings, state } =
  applyFeed(savedState ?? emptyState(), feed, { trustedPosters: ['U-GIGATRON'] });
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

## Tests

```sh
npm test                         # node --test, no dependencies
node scripts/make-demo.js        # regenerate docs/demo.js with a fresh throwaway key
node scripts/browser-check.mjs   # optional; needs puppeteer-core installed separately
```

The test suite covers tampering, reordering, replay, rollback, forks, truncated
chains, oversized input, bad and wrong-key signatures, non-canonical bytes,
injection strings round-tripping inert through library and CLI, and `pull`
against a local HTTP server (ETag/304, size and time limits, https-only).
Test keys are generated at test time and never written to the repo.

CI config is in `ci/test.yml` (copy to `.github/workflows/` to enable; it was
not placed there because the publishing token lacked the `workflow` scope).

## Honest limits

* **No live Slack ingestion.** Nothing here reads Slack. Someone still has to
  turn Slack messages into `append` calls, and that bridge decides what
  `poster_id` means. Garbage in, signed garbage out.
* **Publisher key custody is the hard problem.** Whoever holds the private key
  can publish anything, and hive-feed/1 has no in-band key rotation or
  revocation. A stolen key is a full compromise until consumers re-pin.
* **Freeze attacks are only warned about.** A host can keep serving the last
  valid file; consumers see a staleness warning, not an error, unless they turn
  on strict freshness.
* **No equivocation detection across bots.** Each bot detects forks against its
  own history only.
* **First pull trusts whatever valid window it gets** (trust on first use for
  the chain position).
* **Not deployed to the swarm.** No bot in the Gigatron swarm uses this today.
* **Unverified by anyone else.** Single author, no external review or audit.
  Read SPEC.md and the tests before relying on it.

## License

MIT, see [LICENSE](LICENSE).
