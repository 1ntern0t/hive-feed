# hive-feed/2 specification

Status: draft 0.2 (package v0.2.0), single implementation, not reviewed by anyone else.
hive-feed/2 replaces hive-feed/1 (v0.1.0); v0.1 verifiers reject /2 feeds and
vice versa (format string and unknown-field checks), so a mix fails closed.

## Goal

Let bots learn about new tasks, speed pings, DAO votes, announcements and
results **by polling a static file**, with no webhooks, no inbound ports and no
shared secrets. Authenticity comes from an Ed25519 signature checked against a
public key the consumer pinned out of band.

## Files

A publisher serves two files from any static host (GitHub Pages, S3, a CDN):

| File | Content |
| --- | --- |
| `feed.json` (or `feed.ndjson`) | The feed, canonical encoding (below) |
| `feed.json.sig` | Base64 Ed25519 signature over the **exact bytes** of the feed file, plus an optional trailing newline |

Consumers poll with `If-None-Match: <etag>`; a `304` means nothing changed.
Static hosts ignore query strings, so `?since=<seq>` is an optional hint for
dynamic hosts only; consumers always filter by `seq` themselves.

## Canonical encoding

* JSON values are limited to strings, safe integers, booleans, arrays and
  objects. No floats, no `null`.
* Object keys are sorted by UTF-16 code unit order; no insignificant
  whitespace; strings encoded as by ECMAScript `JSON.stringify`.
* `feed.json` = `canonical(feed) + "\n"`.
* `feed.ndjson` = `canonical(header) + "\n"` followed by one
  `canonical(event) + "\n"` per event, where `header` is the feed object
  without `events`.
* Consumers MUST re-serialize what they parsed and reject the file if the
  result differs from the received bytes. This removes duplicate-key and
  whitespace malleability.
* Encoding is UTF-8; invalid UTF-8 is rejected.

## Feed object

```json
{
  "events": [ ... ],
  "feed_id": "gigatron-main",
  "format": "hive-feed/2",
  "genesis": {
    "created": "2026-10-25T15:00:00.000Z",
    "feed_id": "gigatron-main",
    "pubkey": "<base64 raw 32-byte Ed25519 key that signs until the first rotation>",
    "recovery_digest": "<hex sha256 of a raw recovery public key, or \"\">"
  },
  "head": { "hash": "<hex64>", "seq": 42 },
  "key_id": "<first 16 hex of sha256(raw public key) of the CURRENT key>",
  "key_log": [ <every rotate event ever, oldest first, never pruned; text omitted> ],
  "updated": "2026-10-25T15:00:00.000Z"
}
```

All fields are required; unknown fields are rejected. `genesis` never changes
for the life of a feed. `key_log` is append-only and lets a consumer whose
first pull sees a pruned window still follow every rotation from genesis. `head` is the newest event (`seq` 0 and 64 zeros
for an empty feed). A publisher MAY prune old events (keep a window); `head`
always reflects the true latest event.

## Event object

| Field | Rule |
| --- | --- |
| `type` | `task` \| `speed_ping` \| `dao_vote` \| `announcement` \| `result` \| `rotate` |
| `id` | `[A-Za-z0-9._:-]{1,128}`, unique within the feed |
| `ts` | ISO-8601 UTC `YYYY-MM-DDTHH:MM:SS[.sss]Z`, non-decreasing along the chain |
| `channel` | `[A-Za-z0-9._#-]{1,80}` |
| `poster_id` | `[A-Za-z0-9._:-]{1,64}` – the publisher's *claim* of who posted |
| `url` | `""` or an `https:` URL without credentials, <= 2048 chars |
| `text_digest` | lowercase hex SHA-256 of the UTF-8 text |
| `seq` | integer, `1` for the first event, +1 each event |
| `prev_hash` | `hash` of the previous event; 64 zeros for `seq` 1 |
| `text` | optional, <= 4000 chars, MUST hash to `text_digest` |
| `hash` | hex SHA-256 of `canonical(body)` |
| `sig` | base64 Ed25519 signature over `"hive-feed/2:event:" + canonical(body)` |
| `rotate` | only on `rotate` events, see Key rotation |
| `cosig` | only on `rotate` events: signature by the **next** key over `"hive-feed/2:cosign:" + canonical(body)` |

`body` is the object made of exactly the nine fields `type, id, ts, channel,
poster_id, url, text_digest, seq, prev_hash`, plus `rotate` for rotate events. `text` is outside the body (the
digest covers it), so a publisher may omit text and ship only digests.

Per-event signatures let an event be quoted or archived on its own and still
be checked; the detached file signature binds `head`, `updated` and the window.
The domain prefix keeps event signatures from being confused with file
signatures made by the same key.

## Trust anchor (first pull)

A new bot must not trust the first valid feed it sees: anyone can make a
valid-looking feed with their own key. The anchor is the genesis record:

```
anchor = sha256("hive-feed/2:anchor:" + canonical(genesis))     (64 hex)
display = "hf2:" + first 32 hex in 8 groups of 4                (128 bits)
          e.g. hf2:b794-7865-d87b-b571-7b31-94de-2c9a-2d38
```

* The operator publishes the anchor through a channel bots already trust
  (a Mothership #announcements post, a QR code, a pinned message), never only
  inside the feed or on the feed host. `hive-feed init` prints it.
* A pin is the display form or any hex prefix of the anchor of **at least 32
  hex chars** (128 bits), case-insensitive, separators ignored. Shorter pins
  are refused, not treated as "no pin".
* The anchor commits to the genesis key, the feed id, the creation time and
  the recovery digest. A thief of the genesis key cannot present a look-alike
  genesis with their own recovery key to a bot that pinned the anchor.
* v0.1-style pinning by the base64 genesis public key is still accepted but
  warned about: it does not commit to the recovery digest.
* **Unpinned mode** is refused by default (`HIVE_UNPINNED`). The library
  accepts `allowUnpinned: true` and the CLI `--unpinned-tofu`; both produce a
  loud warning that includes the fingerprint so a human can compare it later.
  After an unpinned first pull, the anchor saved in consumer state pins every
  later pull (trust on first use, explicitly chosen).
* The pin stays valid across rotations: the verifier follows the key history
  from genesis ("the anchor follows the chain").

## Key rotation

A rotate event is a normal chain event (`type: "rotate"`) whose body carries:

```json
"rotate": {
  "mode": "normal" | "recovery",
  "prev_key_id": "<key_id of the key being replaced (the current key)>",
  "next_pubkey": "<base64 raw Ed25519 key>",
  "grace_events": 0..10000,
  "grace_until": "" | "<ISO-8601 UTC>",
  "recovery_pubkey": "" | "<base64, recovery mode only>",
  "next_recovery_digest": "" | "<hex sha256, recovery mode only>"
}
```

**Normal rotation** (planned key change):

* `sig` by the current key (never by a key that is only inside a grace
  window), `cosig` by the next key (proves the publisher holds it).
* `recovery_pubkey` and `next_recovery_digest` MUST be `""`: a normal rotation
  can neither use nor replace the recovery key, so a thief holding only the
  current key cannot disable recovery.
* **Grace window**: after a rotation at seq `r`, a non-rotate event at seq `s`
  may still be signed by the old key only if `s <= r + grace_events` AND
  (`grace_until` is `""` or the event `ts <= grace_until`). Otherwise the old
  key is rejected (`HIVE_KEY_RETIRED`). `grace_events: 0` means no grace. Only
  the immediately previous key gets grace. `ts` is publisher-asserted, so the
  count is the hard bound and the timestamp only shortens it.
* The detached file signature is always by the current (newest) key.
* The reference CLI signs only with the current key; grace exists for events
  that were pre-signed by the old key elsewhere and merged by the library.

**Recovery rotation** (current key lost or stolen):

* Requires `genesis.recovery_digest` (or a later `next_recovery_digest`) to be
  non-empty. `recovery_pubkey` is revealed in the event and its sha256 MUST
  equal the committed digest; `sig` is by the recovery key; `cosig` by the next
  key. No grace: the replaced key is rejected from the next seq on.
* The recovery key is single use. The event may commit a new digest
  (`next_recovery_digest`, must differ) or `""` (no further recovery).
* Recovery may replace any current key, including one a thief installed with
  a normal rotation.
* Recovery is appended to the existing chain; it does not rewrite history.
  Events the thief published before recovery stay in the chain and may already
  have been acted on. If the thief served a different branch to some bots,
  those bots see `HIVE_FORK` and need a manual re-sync.

**Rules for every rotation** (`HIVE_BAD_ROTATION` / `HIVE_ROTATION_REPLAY`):
`prev_key_id` names the current key; `next_pubkey` was never used before
(genesis key, earlier next keys, revealed recovery keys); `next_pubkey` is not
the committed recovery key; `key_log` entries have strictly increasing `seq`,
non-decreasing `ts`, distinct ids and hashes; every rotate event in the window
is byte-identical (hash, sig, cosig) to its `key_log` entry; every `key_log`
entry inside the window's seq range is present in the window; no non-rotate
event sits at a `key_log` seq; no `key_log` entry after `head`.

**What in-band rotation cannot do.** A rotation signed by a stolen key is
indistinguishable from a real one. Normal rotation therefore does **not**
recover from a stolen key; only the pre-committed offline recovery key (or a
new anchor announced out of band) can. If no recovery digest was committed, a
stolen current key is a full compromise until the operator announces a new
anchor out of band and bots re-pin.

## Verification (consumer MUST, fail closed)

1. Reject if the file is larger than the configured limit (default 1 MiB), has
   more than 5000 events or more than 1000 rotations. Enforce a fetch timeout.
2. Refuse without a pin unless unpinned mode was explicitly chosen.
3. Parse; reject non-canonical bytes, unknown or missing fields, bad types,
   `genesis.feed_id != feed_id`. (Parsing happens before the signature check
   because the signing key is derived from the pinned genesis plus the key
   history in the same file; parsing is size-limited and canonical-checked.)
4. Check the pin against `genesis` (`HIVE_ANCHOR_MISMATCH`).
5. Walk `key_log` from the genesis key (rules above). `key_id` MUST equal the
   resulting current key.
6. Verify the detached signature over the exact bytes with the current key.
7. For each event: shape rules, `hash` recomputes, `sig` verifies with the key
   valid at that seq (current key, or the previous key inside its grace
   window; rotate events per `key_log`), `text` matches `text_digest`, `seq`
   contiguous, `prev_hash` links, `ts` non-decreasing, `id` unique. `seq 1`
   must link to 64 zeros.
8. `head` MUST equal the last event in the window.

## Consumer state and policy

The consumer persists `{feed_id, anchor, key_id, key_log_len, key_log_head,
seq, hash, seen_ids, etag}` and, after a successful verification:

* **Anchor**: reject if the feed's anchor differs from the saved one
  (`HIVE_ANCHOR_CHANGED`). The saved anchor also acts as the pin for later
  pulls.
* **Key history**: the `key_log` the consumer already accepted must still be
  an unchanged prefix (same length or longer, entry `key_log_len` has hash
  `key_log_head`), else `HIVE_KEY_CHANGED`. This catches a publisher (or key
  thief) showing a different rotation history than before. New rotations are
  reported as warnings and in `keyChanges`.

* **Rollback**: reject if `head.seq < state.seq`.
* **Fork**: reject if `head.seq == state.seq` with a different hash, if the
  event at `state.seq` in the window has a different hash, or if the event at
  `state.seq + 1` does not link to `state.hash`.
* **Gap**: if the window starts after `state.seq + 1`, linkage cannot be
  checked; warn (the reference code warns; strict consumers may reject).
* **Replay**: only events with `seq > state.seq` are new; additionally skip
  any event whose `id` was seen before (bounded memory of ids).
* **Age**: skip events older than `maxAgeSec` (default 24 h) and events more
  than `maxSkewSec` (default 300 s) in the future.
* **Freshness**: warn (or reject in strict mode) if `updated` is older than
  `maxFeedAgeSec` (default 7 days); this is the only defence against a frozen
  feed and is weak.
* **Poster trust**: accept an event only if `poster_id` is on the consumer's
  own verified-ID list. An empty list trusts nobody.
* Save state only after the whole pipeline succeeds. Save the ETag with it.

## Threat model

| Threat | Mitigation | Residual risk |
| --- | --- | --- |
| **Spoofed feed / MITM / malicious mirror** | Detached Ed25519 signature by the current key, which must chain back to the pinned genesis; per-event signatures; `key_id` check. HTTPS required by the CLI. | A consumer that pins the wrong anchor (e.g. copied from an attacker's README) trusts the attacker. Pin from a channel you already trust. |
| **Spoofed poster** | `poster_id` is only a publisher claim; consumers accept only IDs on their own verified list. | If the publisher itself is wrong about who posted (e.g. a lookalike Slack account), the signature faithfully carries the mistake. |
| **Tampering** | Any byte change breaks the file signature; edited events fail `hash`/`sig`; text must match its digest. | None known beyond key compromise. |
| **Replay** (old file or old event) | Rollback check on `head.seq`, `seq > state.seq` filter, seen-id set, max age, unique ids. | A consumer with no state (first pull) can be served an old but valid feed; the freshness check only warns. |
| **Rollback / freeze** | Persistent `seq`/`hash`; `updated` staleness warning. | An attacker who controls the host can serve the last valid file forever (freeze). Detecting this needs an independent clock signal, e.g. a mandatory heartbeat event plus `strictFreshness`. |
| **Fork / equivocation** (publisher shows different histories to different bots) | Per-consumer fork detection against stored head. | Two consumers are not compared with each other. Gossiping heads between bots would detect equivocation; not implemented. |
| **Reordering / truncation** | Contiguous `seq`, `prev_hash` chain, `head` == last event, canonical bytes. Truncated files fail signature or parse. | Publisher pruning is indistinguishable from truncation of old history; consumers see a gap warning. |
| **Injection in text** | Text is untrusted DATA. It is never executed, evaluated, templated into prompts as instructions, or rendered as HTML. The CLI emits it JSON-escaped (control and bidi characters escaped) inside `{"untrusted_data": true, ...}`; the web page uses `textContent` only under a CSP with no inline script and `connect-src 'none'`. | A downstream LLM agent that pastes event text into its prompt can still be prompt-injected. Consumers must treat event text like any message from a stranger: quote it, never obey it. Signatures do not make content safe. |
| **Resource exhaustion** | Size, event-count, text-length, URL-length and timeout limits; streamed size check during fetch. | Limits are per-request; a consumer polling too often can still be rate-limited by the host. |
| **First-pull impersonation** | Pin the anchor fingerprint (out of band); unpinned mode refused by default, loudly warned when chosen. | A bot that copies the "anchor" from an attacker-controlled page pins the attacker. The out-of-band channel is only as good as the operator's announcement account. |
| **Key compromise (current key)** | Private key file 0600 outside any repo; CLI refuses keys inside a git tree. Pre-committed offline recovery key can force-rotate; normal rotations cannot touch it. | Until recovery is published, the thief can publish anything, including events bots act on. Recovery does not erase events the thief already published. Without a committed recovery key, only an out-of-band re-anchor helps. |
| **Retired key reuse** | Old key rejected after its grace window (`HIVE_KEY_RETIRED`); old key cannot rotate. | A bot with **no state** can be served an older, validly signed history from before the rotation by someone holding the old key (rollback of the key history). Only state, a fresher out-of-band hint, or peer comparison catches this; none of the latter two are implemented. |
| **Recovery key compromise** | Kept offline, revealed only when used, single use. | Thief of the recovery key can take over the feed. Treat it like a root key. |

## Not in scope

Confidentiality (feeds are public), Slack ingestion, consensus between
multiple publishers, comparing heads or key histories between bots, threshold
or multi-signer keys, and deciding what a task or vote *means*.
