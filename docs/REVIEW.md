# hive-feed review packet (v0.3.0)

**The cryptography in hive-feed has not been reviewed by anyone other than
its author.** No audit, no outside review, no production use. This file
exists so an outside reviewer can check it quickly. Until someone has, treat
every guarantee in SPEC.md as a claim, not a fact.

Scope of this packet: the feed format `hive-feed/2`, the peer view summary
format `hive-feed/view-1` (new in 0.3), and the reference implementation in
`src/` (Node) and `docs/app.js` (browser verifier). The Slack bridge
(`src/bridge.js`) does no cryptography of its own beyond calling `appendEvent`;
it is included for its trust decisions (who counts as a sender).

## 1. Primitives and libraries

| Use | Primitive | Library |
| --- | --- | --- |
| Signatures (events, rotations, cosignatures, detached file signature, optional view signature) | Ed25519, pure (RFC 8032, no prehash, no context string) | Node `node:crypto` `sign(null, ...)` / `verify(null, ...)`, which is OpenSSL (Node 20.19.2 ships OpenSSL 3.5.7 on the author's box). Browser page: WebCrypto `{ name: 'Ed25519' }`. |
| Hashes | SHA-256 | `node:crypto` `createHash('sha256')`; WebCrypto `SHA-256` in the browser |
| Key generation | Ed25519 | `generateKeyPairSync('ed25519')` (OpenSSL CSPRNG) |
| Key encoding | Public keys: raw 32 bytes, standard base64 (`^[A-Za-z0-9+/]{43}=$`), wrapped in a fixed SPKI DER prefix `302a300506032b6570032100` for import. Private keys: PKCS#8 PEM, file mode 0600. Signatures: 64 bytes, base64 (`^[A-Za-z0-9+/]{86}==$`). |

No third-party crypto, no dependencies at all. Nothing is encrypted; feeds are
public. There are no MACs and no shared secrets.

## 2. Canonical encoding

`canonical(value)` (`src/canonical.js`):

* Allowed values: strings, safe integers, booleans, arrays, plain objects.
  `null`, floats, `NaN`, `undefined` and non-plain objects throw.
* Object keys sorted by UTF-16 code unit order (JavaScript default sort), no
  whitespace, strings and keys encoded by ECMAScript `JSON.stringify`
  (well-formed: lone surrogates become `\udXXX` escapes).
* `feed.json` = `canonical(feed) + "\n"`; NDJSON = `canonical(header) + "\n"`
  then `canonical(event) + "\n"` per event.
* Verifiers decode UTF-8 with `fatal: true`, `JSON.parse`, re-serialize, and
  reject unless the result is byte-identical to the input. This is meant to
  remove duplicate keys, whitespace, number formats (`1.0`, `-0`, `1e2`),
  escape-choice malleability and BOM games.
* Unknown or missing fields are rejected at every level.

## 3. What is signed and hashed

Domain strings are ASCII prefixes concatenated with the canonical JSON.

| Item | Construction |
| --- | --- |
| Event body | exactly `type, id, ts, channel, poster_id, url, text_digest, seq, prev_hash` (+ `rotate` on rotate events) |
| `text_digest` | `hex(sha256(utf8(text)))`; `text` itself is outside the body and optional |
| Event hash (chain link) | `hex(sha256(canonical(body)))` (**no domain prefix**) |
| Event signature `sig` | `Ed25519(key, "hive-feed/2:event:" + canonical(body))` |
| Rotation countersignature `cosig` | `Ed25519(next_key, "hive-feed/2:cosign:" + canonical(body))` |
| Detached file signature (`feed.json.sig`) | `Ed25519(current_key, exact file bytes)` (**no domain prefix**; the file always starts with `{`) |
| Anchor fingerprint | `hex(sha256("hive-feed/2:anchor:" + canonical(genesis)))`, `genesis = {created, feed_id, pubkey, recovery_digest}` |
| Fingerprint display / pin | `"hf2:"` + first 32 hex (128 bits) in groups of 4; a pin is any >= 32-hex prefix of the anchor |
| `key_id` | first 16 hex (64 bits) of `sha256(raw public key)`; used as a label and for `prev_key_id`, never to select a key for verification |
| `recovery_digest` | `hex(sha256(raw recovery public key))` |
| View summary digest (0.3) | `hex(sha256("hive-feed/view-1:" + canonical(view without digest, sig)))` |
| View signature (0.3, optional) | `Ed25519(observer_key, "hive-feed/view-1:sig:" + digest)` |

## 4. Hash chain

* `seq` starts at 1 and increases by 1. `prev_hash` of seq 1 is 64 zeros;
  otherwise it is the previous event's `hash`. `ts` is non-decreasing. `id`s
  are unique within the window.
* `head = {seq, hash}` of the last event; empty feed has `seq 0` and 64 zeros.
* A publisher may prune old events (a window). `key_log` (every rotate event,
  without text) is never pruned.
* Consumers persist `{seq, hash}` and reject rollback (`head.seq < seq`) and
  forks (same seq different hash, or the next event does not link).

## 5. Genesis fingerprint (trust anchor)

* `genesis` commits to the first signing key, the feed id, the creation time
  and the recovery key digest. It never changes.
* The operator announces the fingerprint out of band. Verifiers refuse to run
  without a pin (`HIVE_UNPINNED`) unless unpinned mode is chosen explicitly.
* Pins shorter than 128 bits are refused. A v0.1-style pin by base64 genesis
  public key is accepted with a warning (it does not commit to the recovery
  digest).

## 6. Rotation, grace and recovery rules

Exact rules are in SPEC.md "Key rotation"; summary:

* **Normal rotation**: rotate event signed by the current key and
  countersigned by the next key. Cannot use or change the recovery key. The
  old key may sign non-rotate events only for seq `<= r + grace_events`
  (max 10000) **and** `ts <= grace_until` if set; only the immediately
  previous key gets grace; rotations are always signed by the current key.
* **Recovery rotation**: signed by the recovery key whose sha256 equals the
  committed digest (revealed in the event), countersigned by the next key, no
  grace, single use; may commit a new recovery digest (must differ).
* **Every rotation**: `prev_key_id` names the current key; the next key was
  never used before (genesis, earlier next keys, revealed recovery keys) and
  is not the committed recovery key; `key_log` strictly increasing seq,
  non-decreasing ts, distinct ids/hashes; rotate events in the window must be
  byte-identical to their `key_log` entries; no `key_log` entry after head.
* Consumers keep `key_log_len` and the hash of the last accepted rotation and
  reject a feed whose `key_log` is not an extension of it (`HIVE_KEY_CHANGED`).

## 7. Peer view comparison (0.3)

`src/compare.js`. A view summary is `{format, feed_id, anchor, head,
key_log (rotation hashes), window: {from_seq, hashes}, observer,
observed_at, observer_pubkey, sig, digest}`. Comparison relies on the chain
property that equal event hashes at seq n imply equal history up to n
(SHA-256 collision resistance). Verdicts: `consistent`, `prefix`, `fork`
(with earliest differing seq; exact only if the windows show the last equal
seq), `different_genesis`, `undetermined` (windows do not overlap). A view
built from a signed feed file the comparing bot verified itself is evidence;
a view summary received from a peer is a claim (its digest and optional
signature only show it was not edited in transit / who produced it).

## 8. Threat model (summary)

Full table: SPEC.md "Threat model". The design goals are:

* A host, mirror, cache or network attacker cannot forge, edit, reorder,
  truncate or splice events without detection by a pinned consumer.
* A consumer with state cannot be rolled back or silently forked.
* Someone else's validly signed feed is rejected on first pull if the anchor
  was pinned.
* A stolen current key can be recovered from only via the offline recovery
  key, and a normal rotation cannot disable recovery.
* Event text is data, never instructions (outside the crypto, but central to
  the swarm use case).
* (0.3) Two bots that exchange views can detect that the publisher (or a key
  thief) showed them different histories.
* (0.3) The Slack bridge trusts only Slack user IDs on a caller-supplied
  allowlist, never display names.

## 9. Known non-goals and accepted weaknesses

* No confidentiality; no anonymity.
* No threshold or multi-signer keys; one key signs at a time.
* No revocation list, no transparency log, no external clock. `ts` and
  `grace_until` are publisher-asserted; the grace event count is the hard
  bound.
* Freeze attacks (serving the last valid file forever) are only warned about.
* A consumer without state can be served an old, validly signed history,
  including one from before a rotation by someone holding a retired key.
* Peer comparison is not gossip: bots must exchange views themselves; nothing
  here transports them. A lying peer can claim a fork that does not exist
  (only signed-feed evidence is proof) and can hide one that does.
* The Slack bridge trusts whatever JSON the operator feeds it. If the
  operator's Slack export or API response is forged, the bridge signs forged
  events. It does not verify Slack's own authenticity (Slack offers no
  signatures on history).
* Ed25519 verification strictness (cofactor, small-order keys, non-canonical
  `R`/`S` encodings) is whatever OpenSSL and the browser implement; hive-feed
  adds no checks of its own beyond length and base64 shape.
* The browser verifier (`docs/app.js`) is a second implementation of the
  same rules written by the same author; agreement between them is tested on
  sample feeds only, not proven.

## 10. Specific questions for a reviewer

1. Event hashes and the detached file signature carry no domain prefix,
   while event signatures, cosignatures and the anchor do. Is there any
   cross-protocol confusion between `sha256(canonical(body))`, file
   signatures over raw feed bytes, and signatures over
   `"hive-feed/2:event:" + ...` / `"hive-feed/view-1:sig:" + digest` made by
   the same key or keys an attacker can choose?
2. Is the canonical JSON check (parse, re-serialize, byte compare) sound
   against malleability in practice, including `__proto__` keys, lone
   surrogates, very deep nesting, and differences between V8 and browser
   `JSON.stringify`/sort?
3. Is a 128-bit fingerprint display / minimum pin length adequate here
   (second-preimage against a chosen `genesis`), or should the display be
   longer?
4. `key_id` is 64 bits and only used as a label and for `prev_key_id`. Can a
   colliding `key_id` be abused anywhere (e.g. consumer state, CLI checks
   `keyId(pub) !== feed.key_id`)?
5. Ed25519 verification: should we reject small-order / non-canonical public
   keys and signatures explicitly (e.g. ZIP-215 vs strict RFC 8032), and do
   OpenSSL 3.x and browser WebCrypto agree on the edge cases?
6. Rotation: are there histories that pass `keySchedule()` but let a holder
   of only a retired key, or only the current key, do more than SPEC.md says
   (disable recovery, extend grace, rotate back, re-use a recovery key)?
7. Grace windows: is mixing a hard event-count bound with a
   publisher-asserted `grace_until` timestamp safe, given `ts` is only
   required to be non-decreasing?
8. Recovery: is revealing the recovery public key only at use time, with a
   single-use rule and a digest commitment, a sound design? Anything better
   that stays this simple?
9. Peer comparison: given views are claims, is the verdict logic (first
   differing hash, prefix check, "hashes agree again after diverging" treated
   as fabricated) correct, and is the exact/upper-bound distinction for
   pruned windows right?
10. Consumer state: is persisting `{anchor, seq, hash, key_log_len,
    key_log_head}` enough to detect key-history rewrites and forks, or is
    there an ordering of pulls that slips through?
11. Bridge: is matching only `message.user` against an allowlist (and
    skipping `bot_message` and edit/delete subtypes) the right trust rule for
    Slack JSON, assuming the JSON itself is authentic?

## 11. How to run the tests

Requirements: Node 20 or newer, no `npm install` needed (zero dependencies).

```sh
git clone https://github.com/1ntern0t/hive-feed && cd hive-feed
npm test                          # node --test test/*.test.js, 101 tests in v0.3.0
node --test test/compare.test.js  # one file
node scripts/browser-check.mjs    # optional browser checks; needs puppeteer-core installed separately
gitleaks detect --source .        # secrets scan, if gitleaks is installed
```

All keys in tests are throwaway keys generated at run time. GitHub Actions
has **not** run on this repository: the workflow is in `ci/test.yml` because
the publishing token lacked the `workflow` scope; a maintainer has to copy it
to `.github/workflows/` to enable it.

## 12. Where to look

| File | What |
| --- | --- |
| `src/canonical.js` | canonical JSON |
| `src/keys.js` | Ed25519 import/export/sign/verify wrappers |
| `src/event.js` | event shape, hash, signing bytes |
| `src/anchor.js` | genesis, fingerprint, pin matching |
| `src/feed.js` | append, rotate, recover, key schedule, full verification |
| `src/consumer.js` | rollback / fork / key-history / replay policy |
| `src/compare.js` | view summaries and peer comparison (0.3) |
| `src/bridge.js` | offline Slack -> feed bridge (0.3) |
| `docs/app.js` | independent browser verifier |
