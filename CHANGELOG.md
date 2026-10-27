# Changelog

## Unreleased (2026-10-27)

### Fixed
- `pull` without `--sig-url` built the signature URL by adding `.sig` to the end of the whole URL string.
  A feed URL with a query string (for example a cache-buster, `feed.json?v=3`) therefore fetched
  `feed.json?v=3.sig`. That is the feed itself, so the pull failed. The `.sig` now goes on the path
  (`feed.json.sig?v=3`), and any `#fragment` is dropped. Tests are in `test/pull.test.js`.
