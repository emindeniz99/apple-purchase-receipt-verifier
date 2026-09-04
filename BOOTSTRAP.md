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

## Packagist (PHP) — blocked on a decision, no publish job exists

**The PHP port cannot be published from this repository as it is laid out.**
Packagist reads `composer.json` from the repository root and nowhere else:
there is no subdirectory field, no monorepo path support, no equivalent of
npm's `repository.directory`. This port's manifest is `php/composer.json`,
which is correct for a monorepo and invisible to Packagist. `release.yml`
therefore has no PHP job, and `README.md` does not list Composer as an install
path.

Nothing here is bootstrappable until the owner picks one of:

- **A — move or duplicate the manifest to the repository root.** A root
  `composer.json` autoloading `EminDeniz99\ApplePurchaseReceiptVerifier\` from
  `php/src/`, with `.gitattributes` `export-ignore` lines trimming the other
  ports out of the published archive. SwiftPM already forces `Package.swift`
  to the root, so the precedent exists. Costs a root `vendor/` in
  `.gitignore`, and an `export-ignore` list that silently decides what every
  PHP consumer receives — a mistake there ships a package with no
  `php/certs/`. Whether GitHub's zipball, which is what Composer downloads,
  honours `export-ignore` was asserted from documentation and never
  reproduced; verify it with a real `git archive` before relying on it. If it
  does not hold, the fallback is shipping the whole repository in the package,
  about 1 MB.
- **B — a read-only mirror repository**, force-pushed from `php/` on every
  tag, with Packagist watching the mirror. Costs a second repository to
  secure, a write credential in this repository's secrets (which the
  read-only-default-token posture deliberately avoids), a tag-ordering hazard
  and permanent drift risk.
- **C — do not publish.** Consumers vendor the source. PHP stays a
  second-class member of a project whose premise is one library across N
  registries.

The PHP port's own recommendation is A, revisited only if `export-ignore`
turns out not to hold.

Once a layout is chosen and landed:

1. Submit the repository at <https://packagist.org/packages/submit>. This
   needs the owner's Packagist account and cannot be automated.
2. Install the **Packagist.org GitHub App** on the repository. Prefer the App
   over the legacy service hook: it stores no secret in this repository.
3. Packagist then imports every existing tag and every future one within
   seconds of the push. There is no OIDC to configure and no token to rotate,
   and no publish job needs to be added to `release.yml`.

## Release budget, unchanged

Maven Central's Usage Center still caps `io.github.emindeniz99` at seven
releases per calendar month, and one tag publishes every language. RubyGems,
crates.io, NuGet and the Go proxy have no monthly cap, so they add no pressure
of their own — but a fix in any one of them still spends a Central release.
