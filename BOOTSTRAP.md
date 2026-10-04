# Bootstrap — the owner actions CI cannot perform

Packages for nine languages, the `aprv-server` binaries and its image ship
from this repository. `release.yml` publishes to the registries that are
already set up; the steps below are the ones that need the account owner, a
browser session, a 2FA code or an owner's decision, and therefore cannot be
automated or run by an agent.

Each section is independent, and an unstarted one no longer breaks a release.
Each of the three publish jobs below asks its registry whether the package
exists at all — RubyGems `/api/v1/gems/<name>.json`, crates.io
`/api/v1/crates/<name>`, NuGet's flat container `index.json` — and reads a 404
as "this section has not been done yet": the job emits a `::notice::` naming
the section, skips its publish steps and concludes success, and
`post-publish-smoke.yml` is told to skip that registry's leg too. Anything
other than 200 or 404 fails the job: an outage must not be mistaken for an
unbootstrapped registry.

RubyGems is the one that asks *after* trying rather than before, because a
pending trusted publisher is meant to publish a gem that does not exist yet
and a check beforehand would skip the very run it was created for.
`publish-rubygems` always attempts OIDC and consults the lookup only if that
fails: no gem and no credentials is an unfinished bootstrap, a gem that exists
is a real authentication failure.

A *half*-configured registry is still a failure, and deliberately so: once
credentials are expected to work, an authentication error is a real one. So do
a section completely rather than partly.

Already bootstrapped, nothing to do: **npm**, **PyPI**, **Maven Central**
(both artifactIds live in the same namespace). **SwiftPM** and the **Go
module proxy** need no bootstrap; both consume the git tag. **GitHub
Releases** carry `aprv.wasm`, the component, the server binaries and
`SHA256SUMS` with the workflow's own token.

Still open: RubyGems, NuGet, Packagist and Docker Hub (a first publish or
a one-time setup each, below); crates.io, held at 0.7 on purpose; two
owner decisions that are not registries, the Maven Central release count
and the Java 8 CI distribution; and the one-time setup for fuzz findings
and OSS-Fuzz.

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
3. Merge the next release pull request — or re-run `release.yml` on the tag
   that skipped. The `publish-rubygems` job copies the release's
   `aprv.wasm` into the gem, checks it against its pin, refuses to push a
   gem missing its entry points or the module, and pushes it.
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

Should RubyGems ever drop pending publishers, the fallback is the shape the
two sections below use: one manual `gem build` + `gem push` with an API key to
create the gem, then a normal trusted publisher on the gem's own page, then
revoke the key.

Open question worth settling here rather than later: `apple_purchase_receipt_verifier`
(underscored) is free today. RubyGems rejects names differing from an existing
gem only in dashes, underscores or case, so publishing the dashed name may make
the underscored one unclaimable. Confirm that at bootstrap; do not publish an
empty stub gem for it.

## crates.io — held at 0.7 until `openssl-sys` accepts OpenSSL 4

The 0.8 core runs on OpenSSL 4 through `aprv-openssl`, and the workspace
builds it with a one-line `[patch.crates-io]` of `openssl-sys`, because
`openssl-sys` 0.9.117 does not accept `openssl-src` 400.x. A patch applies
only inside this workspace: a crates.io build of the crate would get
OpenSSL 3, which `aprv-openssl`'s build script refuses. So the crate stays
at 0.7 on crates.io, and `publish-crates`, the crates smoke in `ci.yml` and
the `crates` leg of `post-publish-smoke.yml` are skipped unless the
repository variable `APRV_PUBLISH_CRATES` is `true`.

1. Done 2026-09-30: the owner opened
   [rust-openssl#2692](https://github.com/rust-openssl/rust-openssl/pull/2692),
   which adds an opt-in `vendored-4` feature to `openssl-sys` (OpenSSL 4
   from `openssl-src` 400.x; `vendored` unchanged). On the fork's CI all
   six new legs pass, and the seven red jobs fail on unchanged master too
   (docs/evidence/2026-09-30-rust-openssl-vendored-4-upstream.md).
   Upstream reviews, merges and releases it.
2. Once a release of `openssl-sys` carries the feature, drop the
   workspace patch, publish `aprv-openssl` first and the core after it,
   and set `APRV_PUBLISH_CRATES` to `true` in the repository's variables.

Until then a Rust user builds from source with a prebuilt OpenSSL 4
(`OPENSSL_NO_VENDOR=1 OPENSSL_DIR=<OpenSSL 4>`, `rust/openssl/README.md`).

The bootstrap itself, whenever publishing resumes: trusted publishing is
configured on the crate's own settings page, so the crate has to exist
first — the same chicken-and-egg npm has.

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

## Go module proxy — already served, nothing to do

There is no registry account, no token and no OIDC. `proxy.golang.org` serves
the module from this repository, and `release.yml`'s `tag-go-module` job
creates the `go/vX.Y.Z` tag that publishes it. From 0.8.0 the Go module
embeds `aprv.wasm`, so the file must be in the tree at the tag: the release
branch commits it (`go/internal/wasm/aprv.wasm` with its `.sha256`), and
`tag-go-module` refuses to tag a tree without both. Both preconditions hold: the
repository is public, and `go/go.mod` declares the final module path,
`github.com/emindeniz99/apple-purchase-receipt-verifier/go`. The proxy has
served every Go tag since `go/v0.4.0`; on 2026-09-28 it listed `v0.4.0`,
`v0.5.1` and `v0.6.0`:

```sh
curl https://proxy.golang.org/github.com/emindeniz99/apple-purchase-receipt-verifier/go/@v/list
```

Because the proxy has fetched the module, a pkg.go.dev badge in `README.md`
would now render.

**A published Go version is immutable and its hash is recorded in
`sum.golang.org` forever.** Deleting or re-pointing a `go/v*` tag does not
un-publish it; it makes every consumer's build fail with a checksum mismatch
that looks exactly like a supply-chain attack. A bad release is fixed forward,
with a new patch version whose `go.mod` carries `retract`.

## The aprv-server image — GHCR needs one click, Docker Hub needs a token

From 0.8.0, `release.yml`'s `publish-image` job pushes the `aprv-server`
image to `ghcr.io/emindeniz99/aprv-server` with the workflow's own
`GITHUB_TOKEN`, so GHCR needs no secret. A package GHCR creates on its first
push is private:

1. After the first 0.8.0 release, open the package's settings on GitHub
   (Packages, `aprv-server`), link it to this repository if it is not, and
   set its visibility to public.

Docker Hub receives the same index, copied by digest, from the
`publish-image-dockerhub` job, which runs in the `docker-hub` environment.
Until that environment holds a token the job prints a notice and succeeds.

1. On Docker Hub, create the namespace (an organisation or the owner's
   account) and a repository `aprv-server` in it.
2. Create an access token with read and write scope on that repository.
3. In this repository's settings, create the environment `docker-hub` and
   add the secret `DOCKERHUB_TOKEN` (the token) and two variables:
   `DOCKERHUB_USERNAME` (the account that owns the token) and
   `DOCKERHUB_NAMESPACE` (where the image goes).

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
  `php/composer.json`, `psr/clock` and `symfony/process` included. No `require-dev`:
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
  `php/src`, the installer or `composer.json`, or carries anything the
  allowlist does not name.
- **`tools/php-consumer-smoke.mjs`** — installs that archive into a throwaway
  project behind a `path` repository and verifies a genuine sandbox receipt
  and the generated StoreKit 2 transaction through `vendor/autoload.php`.
  Both run in the `php-static` job.

The archive holds the two manifests, the two licences, `php/README.md`,
the installer command (`php/bin/aprv-install`) with its
`php/SHA256SUMS`, and the PHP sources. The package ships no binary and
no certificate: the roots are inside the module the `aprv` binary runs,
and `vendor/bin/aprv-install` fetches the binary that matches
`SHA256SUMS` (`php/CI-NOTES.md`). The release branch writes the two
Linux hashes into `SHA256SUMS` before the tag; macOS and Windows get no
line until the release publishes those builds' exact files,
and those platforms use a server URL meanwhile. The open question the old
text flagged is closed. `git archive` honours `export-ignore`,
reproduced by the guard on every run, and GitHub's **zipball** honours it
too: on 2026-09-06 the branch archive at
`archive/refs/heads/feat/packagist-root-manifest.zip` listed exactly the 30
paths the package had then (plus their directory entries) under one
top-level directory, 72 KB.
If a later GitHub change ever stops applying the rules, Composer ships the
whole repository instead, about 1 MB, and nothing else about the layout
changes; the guard only sees `git archive`, so that would show up as a
consumer's oversized vendor directory, not as a red build.

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

## Maven Central — the release count, an owner decision

Maven Central's Usage Center caps `io.github.emindeniz99` at seven
releases, about 80 MB and about 1,000 files per calendar month, and one tag
publishes every language. From 0.8.0 a release deploys two artifactIds,
the main artifact and `-wasm`, and two classifier jars of the static
`aprv-server`, about 10.5 MB in all, so the size allowance binds close
behind the count: seven releases would be about 74 MB. The working budget
in CLAUDE.md is therefore five releases a month, with two kept in reserve.

1. Ask central-support@sonatype.com, or read the Usage Center after the
   first 0.8.0 deployment, whether one deployment of two artifactIds with
   classifiers counts as one release event.
2. Record the answer in CLAUDE.md's release budget, and confirm or change
   the five-a-month rule.

RubyGems, crates.io, NuGet and the Go proxy have no monthly cap, so they
add no pressure of their own — but a fix in any one of them still spends a
Central release.

## The Java 8 CI distribution — an owner decision

Temurin's Java 8 builds end in late 2026. Two CI jobs run on a real Java 8
JVM, `java-runtime-8` (the main artifact) and `java-wasm-runtime-8` (the
`-wasm` server engine), and the Java 8 floor is only a tested claim while
they do.

1. Choose Zulu 8 or Corretto 8.
2. Move both jobs to it before Temurin's last Java 8 build, and say so in
   SUPPORT-MATRIX.md.

## The corpus archive

The nightly `corpus` job runs every package's parity check over the
generated corpora (1,179 receipts and 5,000 mutants, about 200 MB of rows).
They stay out of the repository; `fixtures/corpus.json` pins the archive
by URL and SHA-256, so nothing is set in the repository settings. The
current archive is a release asset of this repository
(docs/rust-core/DECISIONS.md R35):

| Tag | File | Size | SHA-256 |
|---|---|---:|---|
| `corpus-2026-09-29` | `corpus-2026-09-29.tar.gz` | 28,591,520 B | `89b599c52f0448dae22298972db5841a795991edf52df520bea7c545774b956d` |

It was generated from `fixtures/` and the test keys only, and holds no
production receipt. The repository variables `APRV_CORPUS_URL` and
`APRV_CORPUS_SHA256` can be deleted now; nothing reads them. To refresh
it after a release changes the module,
since its rows belong to one module:

1. Build the archive (a `.tar.gz` with the layout `.github/CI-NOTES.md`
   describes) from fixtures and test keys only, and attach it to a
   GitHub release of this repository.
2. Open a PR that changes `url`, `sha256` and `generated` in
   `fixtures/corpus.json`. The job fails on a hash mismatch or a
   missing or malformed file.

## Fuzz findings, OSS-Fuzz and Scorecard: three owner actions

Decided 2026-09-30 (docs/rust-core/DECISIONS.md R37), wired 2026-10-01.
The nightly `rust-fuzz-openssl` job and the eight per-push fuzz jobs in
ci.yml keep each target's output on the runner and print only the target
name and the SHA-256 of a crashing input. `.github/scripts/fuzz-finding.sh`
seals the input and the fuzzer's report with age to the key below, the
job uploads the sealed files for 30 days (as `fuzz-findings-sealed` from
nightly.yml, as `fuzz-findings-sealed-<job>` from ci.yml, for example
`fuzz-findings-sealed-go`), and a Telegram bot sends the repository,
target, input hash and run URL. OpenSSF Scorecard
(`.github/workflows/scorecard.yml`) needs no owner action.

Until the owner does steps 1 and 2, a finding still fails the run:

- with no key file, the job uploads nothing and prints
  `finding withheld: no recipient key; target <name>, input sha256 <hash>`;
  the input and report stay on the runner and disappear with it;
- with no secrets, it prints
  `telegram notice skipped: TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID is not set`.

1. **The age public key.** The wiring takes age keys only. R37 allowed age
   or PGP; one tool, installed from a pinned release checked by SHA-256,
   keeps the job small, and age also accepts an `ssh-ed25519` or
   `ssh-rsa` public key if the owner prefers to reuse one. On the owner's
   machine:

   ```sh
   age-keygen -o ~/aprv-findings.key
   ```

   It prints `Public key: age1...`, the same line the file holds as
   `# public key: age1...`. Commit that public line alone as
   `.github/fuzz/findings-recipient.txt`: one line, `age1` followed by the
   key, a trailing newline, and optionally `#` comment lines. The file
   holding `AGE-SECRET-KEY-1...` stays with the owner and never enters the
   repository. To read a finding, download the `fuzz-findings-sealed`
   artifact (`fuzz-findings-sealed-<job>` from ci.yml) from the failed
   run and run
   `age -d -i ~/aprv-findings.key <target>.tar.age | tar -x`; the tar holds
   the crashing input and `fuzzer.log`.
2. **The Telegram bot.** Create it with @BotFather (`/newbot`), send the
   bot one message from the chat that should be notified, and read that
   chat's id from `https://api.telegram.org/bot<token>/getUpdates`
   (`message.chat.id`). Store both as repository secrets (Settings,
   Secrets and variables, Actions): `TELEGRAM_BOT_TOKEN` (the
   `123456:ABC...` token) and `TELEGRAM_CHAT_ID`.
3. **OSS-Fuzz.** `docs/oss-fuzz/` holds the draft `project.yaml`,
   `Dockerfile` and `build.sh`, and its README the submission steps.
   Replace `OWNER_EMAIL_PLACEHOLDER` in `project.yaml` with the address
   OSS-Fuzz reports to (a committer address in this repository's history,
   on a Google account), then open the pull request to google/oss-fuzz
   from the owner's fork. The draft builds five of the six targets:
   `abi-call` cannot run under OSS-Fuzz until its harness finds the
   module without an environment variable (the README says why).
