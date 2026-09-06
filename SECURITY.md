# Security Policy

This library verifies Apple purchase receipts **locally** — its entire job is
security-sensitive parsing of attacker-suppliable input (PKCS#7 blobs, JWS
tokens). Bugs that make it accept a receipt it should reject are the highest
class of issue here.

[THREAT-MODEL.md](./THREAT-MODEL.md) is the full account: assets, attacker
goals, each mitigation with the test that proves it, the explicit non-goals,
and the residual risks.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
<https://github.com/emindeniz99/apple-purchase-receipt-verifier/security/advisories/new>

Please do not open a public issue for anything exploitable. You can expect an
initial response within a week.

## Supported versions

Only the latest release is supported. Every artifact in a release — npm,
PyPI, Maven Central, SwiftPM, and the registries listed in `BOOTSTRAP.md` as
they come online — is built from the same tag, so a fix ships to all of them
at once.

## Dependency policy

The library ports have almost no runtime dependencies (see each port's
README); the surface is the test and release toolchain. Four rules:

- **Seven-day cooldown.** Every ecosystem in `.github/dependabot.yml` waits
  seven days after a release before proposing it. Manual bumps follow the
  same rule (CONTRIBUTING.md, "Adding or bumping a dependency by hand").
- **No install scripts in CI.** Every `npm ci` in the workflows runs with
  `--ignore-scripts`, and every `composer install` with `--no-scripts`.
- **Lockfile-strict installs in CI.** Every ecosystem with a lockfile commits
  it and installs from it under a flag that fails rather than re-resolves, so
  a hijacked release cannot reach a runner before the cooldown has looked at
  it: `npm ci`, `cargo --locked`, `uv sync --locked`, `composer install`,
  `BUNDLE_FROZEN=true`, `RestoreLockedMode` for NuGet, `swift
  --force-resolved-versions`, and Go's default `-mod=readonly` against
  `go.sum`. Two legs resolve from ranges on purpose, because resolving is
  what they test: `php-lowest` (`composer update --prefer-lowest`) and
  Java, which pins exact versions and has no lockfile format.
- **No long-lived registry tokens.** npm, PyPI, RubyGems, crates.io and NuGet
  publish through OIDC trusted publishing from `release.yml`; there is no
  token to steal from a laptop or a workflow. Maven Central has no OIDC
  path, so its credentials live on the `maven-central` GitHub environment,
  reachable from that one job only.

Every workflow pins actions to a commit SHA, checks out with
`persist-credentials: false`, and runs with a read-only `GITHUB_TOKEN`
except where a publish job asks for `id-token: write`; `zizmor` checks that
on every push.

## What counts

Especially interesting:

- Signature or certificate-chain validation bypasses (forged receipt accepted)
- Trust-anchor confusion (accepting chains not rooted in the pinned Apple roots
  in `certs/`)
- Parser differentials between the nine language implementations — if two
  disagree on the same receipt, one of them is wrong
- ASN.1/JWS parsing crashes on malformed input (DoS in a server context)
