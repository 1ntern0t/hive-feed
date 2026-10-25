# hive-feed/1 specification

Status: draft 0.1, single implementation, not reviewed by anyone else.

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
  "format": "hive-feed/1",
  "head": { "hash": "<hex64>", "seq": 42 },
  "key_id": "<first 16 hex of sha256(raw 32-byte public key)>",
  "updated": "2026-10-25T15:00:00.000Z"
}
```

Unknown fields are rejected. `head` is the newest event (`seq` 0 and 64 zeros
for an empty feed). A publisher MAY prune old events (keep a window); `head`
always reflects the true latest event.

## Event object

| Field | Rule |
| --- | --- |
| `type` | `task` \| `speed_ping` \| `dao_vote` \| `announcement` \| `result` |
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
| `sig` | base64 Ed25519 signature over `"hive-feed/1:event:" + canonical(body)` |

`body` is the object made of exactly the nine fields `type, id, ts, channel,
poster_id, url, text_digest, seq, prev_hash`. `text` is outside the body (the
digest covers it), so a publisher may omit text and ship only digests.

Per-event signatures let an event be quoted or archived on its own and still
be checked; the detached file signature binds `head`, `updated` and the window.
The domain prefix keeps event signatures from being confused with file
signatures made by the same key.

## Verification (consumer MUST, fail closed)

1. Reject if the file is larger than the configured limit (default 1 MiB) or
   has more than 5000 events. Enforce a fetch timeout.
2. Verify the detached signature over the exact bytes with the **pinned**
   public key. Never take the key from the feed itself.
3. Parse; reject non-canonical bytes, unknown fields or bad types.
4. `key_id` MUST match the pinned key.
5. For each event: shape rules, `hash` recomputes, `sig` verifies, `text`
   matches `text_digest`, `seq` contiguous, `prev_hash` links, `ts`
   non-decreasing, `id` unique. `seq 1` must link to genesis.
6. `head` MUST equal the last event in the window.

## Consumer state and policy

The consumer persists `{feed_id, key_id, seq, hash, seen_ids, etag}` and,
after a successful verification:

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
| **Spoofed feed / MITM / malicious mirror** | Detached Ed25519 signature against a pinned key; per-event signatures; `key_id` check. HTTPS required by the CLI. | A consumer that pins the wrong key (e.g. copied from an attacker's README) trusts the attacker. Pin from a channel you already trust. |
| **Spoofed poster** | `poster_id` is only a publisher claim; consumers accept only IDs on their own verified list. | If the publisher itself is wrong about who posted (e.g. a lookalike Slack account), the signature faithfully carries the mistake. |
| **Tampering** | Any byte change breaks the file signature; edited events fail `hash`/`sig`; text must match its digest. | None known beyond key compromise. |
| **Replay** (old file or old event) | Rollback check on `head.seq`, `seq > state.seq` filter, seen-id set, max age, unique ids. | A consumer with no state (first pull) can be served an old but valid feed; the freshness check only warns. |
| **Rollback / freeze** | Persistent `seq`/`hash`; `updated` staleness warning. | An attacker who controls the host can serve the last valid file forever (freeze). Detecting this needs an independent clock signal, e.g. a mandatory heartbeat event plus `strictFreshness`. |
| **Fork / equivocation** (publisher shows different histories to different bots) | Per-consumer fork detection against stored head. | Two consumers are not compared with each other. Gossiping heads between bots would detect equivocation; not implemented. |
| **Reordering / truncation** | Contiguous `seq`, `prev_hash` chain, `head` == last event, canonical bytes. Truncated files fail signature or parse. | Publisher pruning is indistinguishable from truncation of old history; consumers see a gap warning. |
| **Injection in text** | Text is untrusted DATA. It is never executed, evaluated, templated into prompts as instructions, or rendered as HTML. The CLI emits it JSON-escaped (control and bidi characters escaped) inside `{"untrusted_data": true, ...}`; the web page uses `textContent` only under a CSP with no inline script and `connect-src 'none'`. | A downstream LLM agent that pastes event text into its prompt can still be prompt-injected. Consumers must treat event text like any message from a stranger: quote it, never obey it. Signatures do not make content safe. |
| **Resource exhaustion** | Size, event-count, text-length, URL-length and timeout limits; streamed size check during fetch. | Limits are per-request; a consumer polling too often can still be rate-limited by the host. |
| **Key compromise** | Private key file 0600 outside any repo; CLI refuses to write keys inside a git tree. | Whoever holds the key can publish anything. Key custody is the hard problem (see below). |

## Key rotation

hive-feed/1 has no in-band rotation. Rotation is deliberate and out of band:

1. Publisher generates a new key and announces the new public key through an
   already-trusted channel (for example a signed `announcement` event in the
   old feed whose text contains the new key, *and* a second channel).
2. Publisher starts a **new feed** (`feed_id` may stay; `seq` restarts or
   continues, the new key signs everything).
3. Consumers re-pin and reset state for that feed. The reference consumer
   refuses a `key_id` change (`HIVE_KEY_CHANGED`) so a stolen-then-swapped
   key cannot silently take over.

If the old key is compromised, an announcement signed by it proves nothing;
only the out-of-band channel counts. A future version could add a
pre-committed next-key hash (KERI-style pre-rotation); not implemented.

## Not in scope

Confidentiality (feeds are public), Slack ingestion, consensus between
multiple publishers, and deciding what a task or vote *means*.
