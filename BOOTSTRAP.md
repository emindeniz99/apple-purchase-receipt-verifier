# Bootstrap — the owner actions CI cannot perform

Nine implementations ship from this repository. `release.yml` publishes the
ones whose registries are already set up; the steps below are the ones that
need the account owner, a browser session, or a 2FA code, and therefore cannot
be automated or run by an agent.

Each section is independent. Do a section completely before the next release
pull request is merged, because `release.yml` runs every publish job on every
tag — a registry that is half-configured fails the tag run rather than being
skipped.

Already bootstrapped, nothing to do: **npm**, **PyPI**, **Maven Central**.
**SwiftPM** never needed a bootstrap; it consumes the git tag.

## RubyGems

RubyGems supports *pending* trusted publishers — a publisher configured
against a gem name before the gem exists — so the first Ruby publish can go
through `release.yml` with no manual `gem push`.

1. Create the GitHub environment `rubygems` on this repository, with no
   secrets. Its only job is to constrain who can trigger a publish, the way
   `pypi` already does.
2. On rubygems.org → profile → **Pending trusted publishers** → Create:
   - Gem name: `apple-purchase-receipt-verifier`
   - Repository owner: `emindeniz99`
   - Repository name: `apple-purchase-receipt-verifier`
   - Workflow filename: `release.yml`
   - Environment: `rubygems`
3. Merge the next release pull request. The `publish-rubygems` job builds the
   gem, refuses to push one missing its entry points or `certs/`, and pushes
   it.
4. Confirm the pending publisher became a normal one on the gem's "Trusted
   publishers" page, and that the account owns the gem:

   ```sh
   gem owner apple-purchase-receipt-verifier
   ```

5. Require MFA on the gem. RubyGems gates owner-side operations on 2FA per
   operation, so this needs the owner's own code:

   ```sh
   gem owner apple-purchase-receipt-verifier --otp <code>
   ```

Open question worth settling here rather than later: `apple_purchase_receipt_verifier`
(underscored) is free today. RubyGems rejects names differing from an existing
gem only in dashes, underscores or case, so publishing the dashed name may make
the underscored one unclaimable. Confirm that at bootstrap; do not publish an
empty stub gem for it.

## crates.io

Trusted publishing is configured on the crate's own settings page, so the
crate has to exist first — the same chicken-and-egg npm has.

1. From a clean checkout, with `git status` clean and `HEAD` pushed
   (`cargo publish` packs the working tree, not a commit), publish the current
   version with a scoped API token:

   ```sh
   cd rust
   cargo publish --token <scoped crates.io token>
   ```

   Publish at the version `version.txt` currently names, not the one
   release-please is about to propose, so the automated run has a free version
   to take.
2. On crates.io → the crate's Settings → Trusted Publishing, add GitHub with
   repository `emindeniz99/apple-purchase-receipt-verifier` and workflow
   `release.yml`. Then revoke the token from step 1.
3. Merge the next release pull request and let `publish-crates` cut that
   version, which proves the chain end to end.

Check before scheduling step 1: crates.io may by now allow a *pending* trusted
publisher for a crate that does not yet exist, the way PyPI does. If it does,
step 1 disappears.

A crates.io publish is irrevocable — a yank hides a version, it never deletes
it.

## NuGet

The package id is `ApplePurchaseReceiptVerifier`, not
`apple-purchase-receipt-verifier`. NuGet's search splits camel case, so "apple
receipt" still finds it, and the id can never be changed after the first
publish.

1. Publish the current version by hand with an API key — NuGet's trusted
   publishing cannot create a package that does not exist:

   ```sh
   cd dotnet
   dotnet pack src/ApplePurchaseReceiptVerifier -c Release -o ./nupkg
   dotnet nuget push ./nupkg/ApplePurchaseReceiptVerifier.<version>.nupkg \
     --source https://api.nuget.org/v3/index.json --api-key <key>
   ```

2. Delete that API key on nuget.org.
3. On nuget.org → the package → Trusted Publishing, add package
   `ApplePurchaseReceiptVerifier`, repository
   `emindeniz99/apple-purchase-receipt-verifier`, workflow file `release.yml`,
   user `emindeniz99`.
4. Merge the next release pull request and let `publish-nuget` cut that
   version. After this, no NuGet API key exists anywhere in the repository.

## Go module proxy

There is no registry account, no token and no OIDC. `proxy.golang.org` serves
the module from this repository, and `release.yml`'s `tag-go-module` job
creates the `go/vX.Y.Z` tag that publishes it. Three preconditions, and only
the third needs doing:

1. The repository must be public. `proxy.golang.org` cannot fetch a private
   repository.
2. `go/go.mod` must declare the final module path on the tagged commit. It
   does: `github.com/emindeniz99/apple-purchase-receipt-verifier/go`.
3. Verify the module resolves once, by hand, without burning a tag — a
   pseudo-version needs no tag at all:

   ```sh
   GOPROXY=direct go list -m \
     github.com/emindeniz99/apple-purchase-receipt-verifier/go@<commit-sha>
   ```

   That proves the module path, the subdirectory prefix and the zip contents.

Then, and only after the first `go/v*` tag exists, add the pkg.go.dev badge to
`README.md`; it renders only after the first proxy fetch.

**A published Go version is immutable and its hash is recorded in
`sum.golang.org` forever.** Deleting or re-pointing a `go/v*` tag does not
un-publish it; it makes every consumer's build fail with a checksum mismatch
that looks exactly like a supply-chain attack. A bad release is fixed forward,
with a new patch version whose `go.mod` carries `retract`.

## Packagist (PHP) — layout A is landed, two owner actions remain

**The PHP package is the repository root.** Packagist reads `composer.json`
from a repository root and nowhere else: no subdirectory field, no monorepo
path support, no equivalent of npm's `repository.directory`. So the root
carries a `composer.json` that declares the same package as
`php/composer.json` and autoloads `EminDeniz99\ApplePurchaseReceiptVerifier\`
from `php/src/`, while the port itself stays in `php/`. This is layout A of
the three that used to be listed here; B (a force-pushed mirror repository)
and C (do not publish) were dropped with it.

What landed:

- **`composer.json` at the root** — the package Packagist and Composer see.
  Same name, description, licence, keywords and `require` as
  `php/composer.json`, `psr/clock` included. No `require-dev`:
  `php/composer.json` stays the development manifest, and `php/composer.lock`
  stays the lockfile every CI leg installs.
- **A `.gitattributes` allowlist** — `* export-ignore`, then each shipped path
  named back in. Composer installs GitHub's zipball of a tag and a zipball is
  a `git archive`, so these rules are the package's file list. The allowlist
  direction was chosen over naming the ports to exclude because its failure
  mode is loud: something the package needs goes missing, rather than a tenth
  port added next year riding along inside the PHP package unnoticed. The
  reasoning is in the file.
- **`tools/check-php-package.mjs`** — fails CI when the two manifests'
  `require` or `autoload` disagree, and when the real `git archive` is missing
  `php/src`, the three `php/certs/*.cer` or `composer.json`, or carries
  anything the allowlist does not name.
- **`tools/php-consumer-smoke.mjs`** — installs that archive into a throwaway
  project behind a `path` repository and verifies a genuine sandbox receipt
  and the generated StoreKit 2 transaction through `vendor/autoload.php`.
  Both run in the `php-static` job.

The archive is 30 files: the two manifests, the two licences,
`php/README.md`, the three pinned roots and 22 PHP sources. The open question
the old text flagged is half closed. `git archive` honours `export-ignore`,
reproduced by the guard on every run; whether GitHub's **zipball** honours it
cannot be tested before this is on a branch GitHub serves. Verify it after
merge by downloading
<https://github.com/emindeniz99/apple-purchase-receipt-verifier/archive/refs/heads/main.zip>
and listing it: the same 30 paths, under one top-level directory. If it turns
out not to hold, Composer ships the whole repository instead, about 1 MB, and
nothing else about the layout changes.

One consequence worth knowing, because it reaches past Composer: GitHub builds
the "Source code (zip)" asset on every Release from the same archive, so that
asset is the PHP package rather than the whole monorepo. Nothing in
`.github/workflows/` consumes it, and SwiftPM and the Go module proxy clone
the repository rather than download an archive.

What remains, both the owner's and neither automatable:

1. Submit the repository at <https://packagist.org/packages/submit>. This
   needs the owner's Packagist account.
2. Install the **Packagist.org GitHub App** on the repository. Prefer the App
   over the legacy service hook: it stores no secret in this repository.

Packagist then imports every existing tag and every future one within seconds
of the push. There is no OIDC to configure and no token to rotate, and no
publish job is added to `release.yml` — which is why the PHP port is the one
registry with nothing in it. **The first Packagist version is the first tag
cut after this lands**; earlier tags are importable but their archives predate
the root manifest, so Packagist will skip them.

## Release budget, unchanged

Maven Central's Usage Center still caps `io.github.emindeniz99` at seven
releases per calendar month, and one tag publishes every language. RubyGems,
crates.io, NuGet and the Go proxy have no monthly cap, so they add no pressure
of their own — but a fix in any one of them still spends a Central release.
