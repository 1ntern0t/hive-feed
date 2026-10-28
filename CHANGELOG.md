# Changelog

## 0.3.0 (2026-10-28)

Feed format unchanged (`hive-feed/2`). The cryptography is still unreviewed.

### Added
- `docs/REVIEW.md`: review packet for an outside crypto reviewer (primitives, canonical encoding,
  hash chain, anchor derivation, rotation/grace/recovery rules, threat model, non-goals, questions,
  how to run the tests).
- Offline Slack -> feed bridge (`src/bridge.js`, `hive-feed bridge-slack`). Trust is the Slack user
  ID on a caller-supplied allowlist only; display names are ignored; no built-in IDs. Dedupe by
  channel + ts. No network calls, no Slack tokens. Examples in `examples/`.
- Peer history comparison (`src/compare.js`, `hive-feed view`, `hive-feed compare`) with the
  `hive-feed/view-1` view summary (digest, optional observer signature). Reports consistent,
  prefix, fork (earliest divergence seq), different genesis or undetermined.
- `pull --save-feed` keeps the verified feed and signature; library `pull()` returns `bytes`/`sig`.

### Fixed
- CLI `pull` failed when `--timeout-ms` or `--max-bytes` was not given (undefined values overrode
  the defaults, so `AbortSignal.timeout(undefined)` threw).

### Tests
- 81 -> 101 (`test/bridge.test.js`, `test/compare.test.js`, one CLI pull test, pull bytes check).

## 0.2.x fixes (2026-10-27, merged in PR #1)

### Fixed
- `pull` without `--sig-url` built the signature URL by adding `.sig` to the end of the whole URL string.
  A feed URL with a query string (for example a cache-buster, `feed.json?v=3`) therefore fetched
  `feed.json?v=3.sig`. That is the feed itself, so the pull failed. The `.sig` now goes on the path
  (`feed.json.sig?v=3`), and any `#fragment` is dropped. Tests are in `test/pull.test.js`.
- `.gitignore` now covers the `browser-check.png` screenshot written by `scripts/browser-check.mjs`.
