# Security policy

## Status

hive-feed is an early, single-author prototype. It has not been audited or
independently reviewed, and nobody runs it in production. Do not use it to
move money, points or credentials without your own review.

## Reporting

Open a GitHub issue for non-sensitive problems. For something exploitable,
use GitHub's private vulnerability reporting on this repository
("Security" tab -> "Report a vulnerability") instead of a public issue.

## Rules this project follows

* **No private keys in the repository, ever.** `.gitignore` excludes `*.key`,
  `*.pem`, `*.p8`, `keys/` and `secrets/`. `hive-feed keygen` writes the
  private key with mode 0600 using exclusive create, refuses paths inside a git
  work tree, and prints only the public key and key id.
* Tests and the demo page use **throwaway keys generated at run time** and kept
  in memory. The demo public key in `docs/demo.js` has no stored private half.
* Zero runtime dependencies; crypto is `node:crypto` (Ed25519, SHA-256) and
  WebCrypto in the browser page.
* Verification fails closed: any error means "do not update state, do not act".
* Event text is untrusted data and is never executed or rendered as HTML.

## Known weaknesses

See the threat model in [SPEC.md](SPEC.md#threat-model) and "Honest limits"
in the README: freeze attacks are only warned about, equivocation between
consumers is not detected, there is no in-band key rotation, and publisher key
custody is left to the operator.

## Publisher key custody checklist

* Generate the key on the machine that publishes, outside any repo:
  `hive-feed keygen --out ~/.config/hive-feed/publisher.key`.
* Keep it 0600, out of backups that sync to shared drives, out of CI logs.
* If you publish from CI, store the key in the CI secret store, scope it to one
  protected branch, and accept that anyone who can change that workflow can
  sign as you.
* Write down how consumers will learn about a new key *before* you need one.
