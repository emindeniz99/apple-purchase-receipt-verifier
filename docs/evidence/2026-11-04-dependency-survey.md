# Dependency survey follow-up, 2026-11-04

**Question.** No Dependabot pull request is open. Which dependency updates are past the seven-day cooldown, meaning a newer release published on or before 2026-10-28? Which ones should Dependabot have proposed already, and which will it propose next? This follow-up also checks what happened to the releases the 2026-10-31 survey held for the cooldown.

It decides what the next maintenance pass takes and whether Dependabot needs a configuration change.

## Method

This survey read `main` at `b092a605` (2026-11-04).

1. `parse.py` from [the 2026-10-31 survey](./2026-10-31-dependency-survey/) read 1,216 locked or pinned versions:

   | Ecosystem | Versions |
   |---|---|
   | crates.io | 636 |
   | npm | 304 |
   | Packagist | 65 |
   | Maven | 64 |
   | NuGet | 62 |
   | RubyGems | 47 |
   | SwiftPM | 15 |
   | Go | 11 |
   | PyPI | 10 |

2. `newer.py` ran with `CUT=0000-00-00`, so it listed every newer release with its date. `classify.py` split each list at 2026-10-28.
3. `osv.py` sent 833 unique versions to OSV.
4. `newer.py` compares each package against the highest version locked anywhere in the repository. Because of that, the lagging copies of `golang.org/x/sys` (v0.47.0 in `go/`), JUnit (5.14.4 in `java/` and `java-wasm/`), swift-crypto and WasmKit (in `swift/bench` and `swift/fuzz`) were checked by hand. The direct crates in each Cargo lockfile were checked with `crates_direct.py`.
5. Action tags were read with `acts.sh`. Their dates are tag or commit dates from `tagdate.sh`, because api.github.com was out of reach from this environment.
6. Image digests were read from the registries with `digest.py` and `gcr.py`. Docker Hub push times came from its tags API.
7. Dependabot's pull requests were listed through the REST API.

The helpers are in [2026-11-04-dependency-survey/](./2026-11-04-dependency-survey/).

## Results

### Held on 2026-10-31, re-checked

| Held release | Published | Now | Taken? |
|---|---|---|---|
| endive 1.2.0 (runtime and compiler plugin) | 2026-10-30 | Still in the cooldown until 2026-11-06 | No |
| System.Text.Json 10.0.14 | 2026-10-25 | Past the cooldown | No, 10.0.13 is still locked |
| symfony/process 7.4.22 | 2026-10-25 | Past the cooldown | No, 7.4.21 is still locked |
| rustix 1.1.6 (aprv-server) | 2026-10-27 | Past the cooldown, transitive | No |
| log 0.4.35 and encoding_rs 0.8.44 (aprv-server) | 2026-10-30 | Still in the cooldown | No |
| platformdirs 4.13.6, 4.13.7 and 4.14.0 | 2026-10-27 to 2026-10-28 | Past the cooldown | No, 4.13.5 is still locked |
| oxlint 1.90.0 | 2026-10-27 | Past the cooldown | No |
| jco 1.40.0 | 2026-10-28 | Past the cooldown | No |
| mypy 2.4.1 | 2026-10-28 | Past the cooldown | No |
| ruff 0.17.3 | 2026-10-27 | Past the cooldown | No |
| phpstan 2.3.3 and 2.3.4 | 2026-10-27 and 2026-10-28 | Past the cooldown | No |
| rubocop 1.92.2 | 2026-10-29 | Still in the cooldown | No. tools.gemfile is not watched |

Two items from the 2026-10-31 "known and not reachable" table have moved since:
- minimatch is now overridden to 11.0.4 (4b7ad0a0), a security fix taken inside the cooldown.
- aprv-server moved to Wasmtime 50.0.1 (#462), which fixes RUSTSEC-2026-0422 to 0424.

### Past the cooldown, and Dependabot will propose

These are direct dependencies in watched directories. None of them fixes an advisory that OSV lists.

| Ecosystem | Directory | Package | Locked → target | Target published | Ships to users |
|---|---|---|---|---|---|
| npm | /node | @bytecodealliance/jco | 1.39.0 → 1.40.0 | 2026-10-28 14:32Z | Its generated JavaScript does |
| npm | /node | oxlint | 1.89.0 → 1.90.0 | 2026-10-27 | No |
| uv | /python | platformdirs | 4.13.5 → 4.14.0 | 2026-10-28 18:27Z | Runtime dependency, lockfile only |
| uv | /python | mypy | 2.4.0 → 2.4.1 | 2026-10-28 19:21Z | No |
| uv | /python | ruff | 0.17.2 → 0.17.3 | 2026-10-27 | No |
| nuget | /dotnet | System.Text.Json | 10.0.13 → 10.0.14 | 2026-10-25 | Yes, the netstandard2.0 dependency |
| nuget | /dotnet | Microsoft.Testing.Platform | 2.5.1 → 2.5.2 | 2026-10-27 | No |
| composer | /php | symfony/process | 7.4.21 → 7.4.22 | 2026-10-25 | The constraint ships, the lockfile does not |
| composer | /php | phpstan/phpstan | 2.3.1 → 2.3.4 | 2026-10-28 22:38Z | No |
| cargo | /rust | jsonschema (aprv-wire dev) | 0.60.1 → 0.60.2 | 2026-10-26 | No |
| docker | /tools/reproduce | debian:trixie-slim digest | 2026-10-05 build → 2026-10-28 push | 2026-10-28 20:25Z | No |
| github-actions | / | shivammathur/setup-php | 2.37.2 → 2.40.0 | 2026-10-08 | No |
| github-actions | / | ossf/scorecard-action | v2.4.4 → v2.5.0 | 2026-10-11 | No |
| github-actions | / | actions/setup-java | v6.0.1 → v6.1.0 | 2026-10-14 | No |
| github-actions | / | github/codeql-action | v4.38.2 → v4.39.1 | 2026-10-21 | No |
| github-actions | / | actions/setup-python | v7.0.0 → v7.1.0 | 2026-10-21 | No |
| github-actions | / | rust-lang/crates-io-auth-action | v1.0.5 → v1.0.6 | 2026-10-21 | No |
| github-actions | / | ruby/setup-ruby | v1.328.0 → v1.335.0 | 2026-10-24 | No |
| github-actions | / | gradle/actions (setup-gradle) | v6.4.0 → v6.4.1 | 2026-10-28 | No |
| github-actions | / | astral-sh/setup-uv | v10.3.0 → v10.3.3 | 2026-10-28 | No |

For an action, the date is the tag's date, not the release's. Every action pin was checked against its tag comment, and all of them match. Five of the targets were published on 2026-10-28. A run that measures exactly seven days from 2026-11-04 would offer an earlier patch for some of them: platformdirs 4.13.7, phpstan 2.3.3 or setup-uv v10.3.2.

### Why no Dependabot pull request is open

Dependabot runs on Saturdays at about 10:42 UTC. The last scheduled run was on 2026-10-31. It opened 15 pull requests, and all of them were merged or closed that day. That run's cutoff was 2026-10-24 10:42. Every non-action row above was published between 2026-10-25 and 2026-10-28, so each one missed that run by a few days. The next run, on 2026-11-07, will propose them. It will also propose direct dependencies published up to 2026-10-31 10:42, for example wat 1.263.0, endive 1.2.0 and setup-ruby v1.336.0.

The actions are a different case. The five grouped action pull requests opened on 2026-10-17 (#406 to #410) stayed open until 2026-10-31 15:57. Dependabot's default `open-pull-requests-limit` for an entry is five, so the 2026-10-24 and 2026-10-31 runs could not open any action pull request. setup-php 2.40.0 and codeql v4.38.3, both from 2026-10-08, were already eligible on 2026-10-17, and that run opened exactly five. This explanation is inferred from the pull request history. The Dependabot job logs were not read. The same limit applies on 2026-11-07: nine actions are due, and `group-by: dependency-name` gives each one its own pull request, so that run opens five and the rest wait until some are merged. The pull request that adds this note groups all action updates into one pull request (see [What changed](#what-changed)).

### Still held by the cooldown

Shipped to consumers:
- endive 1.2.0 (2026-10-30, the `-wasm` artifact, whose publishing is held)
- openssl 0.10.82 (2026-11-01)
- jiff 0.2.39 (2026-11-02)
- log 0.4.35 and encoding_rs 0.8.44 in aprv-server (2026-10-30)
- swift-crypto 5.1.0 and 5.1.1 (2026-11-02 and 2026-11-03)
- platformdirs 4.14.2 to 4.14.4

Dev and CI:
- cc 1.11.0 (2026-11-02)
- wat 1.263.0 and the wasm-tools 1.263.0 toolchain pin (2026-10-30)
- jco 1.41.0
- oxlint 1.91.0
- wrangler 4.156.1 to 4.157.0
- mypy-extensions 1.2.0
- phpstan 2.3.5
- spotless-maven-plugin 3.11.0
- rubocop 1.92.2
- setup-dotnet v6.1.0
- codeql v4.39.2
- the distroless static image, whose current digest was uploaded on 2026-10-31

### Ignored or decided

- OpenSSL 4.1.0 (2026-10-23). The core stays on 4.0.x and revisits around 2026-12-01 or at 4.1.1 ([review](./2026-10-31-openssl-4.1-review.md), ROADMAP.md). No 4.1 `openssl-src` release exists yet.
- openssl-sys 0.9.118 (2026-11-01) is ignored because the vendored patch is 0.9.117. `openssl-src` 300.x is ignored. foreign-types 0.4 and 0.5 are ignored.
- wit-bindgen is ignored. 0.63.0 is the newest release anyway.
- `@types/node` 26 is ignored. 20.19.43 is the newest 20.x.
- JUnit 6 is ignored in `java/` and `java-wasm/`. 5.14.4 is the newest 5.x.
- Spring Boot 4.1 is ignored. 4.0.9 is the newest 4.0.x.
- `golang.org/x/sys` 0.48 and 0.49 are ignored in `go/`, because both need Go 1.26.

### Floors

- PHP. The platform is pinned to 8.2.0. PHPUnit 12 needs PHP 8.3, PHPUnit 13 needs 8.4.1 and symfony/process 8 needs 8.4.1. 11.5.57 and 7.4.22 are the newest releases that fit.
- Rust. jsonschema 0.60.2 declares MSRV 1.85.0, which is exactly the floor. No other candidate exceeds it.
- `rust/server/Cargo.toml` declares `rust-version = "1.85.0"`, but `wasmtime` 50.0.1 needs 1.97.0. That claim is not tested, because the server is outside the workspace and is built with 1.99.1. The pull request that adds this note corrects the value.

### Past the cooldown, with no updater

Dependabot updates only direct dependencies and watched manifests, so these rows will not get a pull request:

- Cargo lockfile entries.
  - `rust/Cargo.lock` has 15 semver-compatible updates past the cooldown, among them jiff-tzdb 0.1.8 → 0.1.9 (2026-10-06). jiff-static embeds jiff-tzdb in `aprv.wasm` at build time, so updating it changes the module's bytes.
  - `rust/server/Cargo.lock` has 16, among them hyper 1.12.0 and rustix 1.1.6.
- npm. Most of the 136 entries past the cooldown are transitive. The `@bytecodealliance/weval` override is 0.5.0, and 0.5.1 came out on 2026-10-12.
- `swift/bench` and `swift/fuzz`. They resolve swift-crypto 5.0.0 and WasmKit 0.4.1, while the root resolves 5.0.3 and 0.4.2. Both packages declare only the library by path, so their Dependabot entries likely have no direct dependency to move. swift-asn1 1.7.4 (2026-10-08) is transitive everywhere.
- Ruby. `ruby/gemfiles/*.gemfile` are unwatched by design: csv, fileutils, listen and uri have patches.
- Workflow pins.
  - cbindgen is installed at 0.29.0, and 0.29.4 came out on 2026-06-09.
  - spectral-cli is at 6.16.3, and 6.17.0 came out on 2026-10-01.
  - Gradle is at 9.7.1, and 9.8.2 came out on 2026-10-19.
- Workflow container digests.
  - swift:6.3 has a new digest, pushed on 2026-10-27.
  - The distroless java17/21/25-debian13 images are pinned to 2026-09-13 uploads.
  - The uv python3.11 to 3.14 alpine images are pinned to 2026-09-28 builds.
  - eclipse-temurin:21-jre-noble is pinned to a 2026-09-25 build.

  No Dependabot commit has ever moved a workflow container digest. That contradicts the header of `dependabot.yml`, which says the swift container is kept current. Whether the github-actions ecosystem updates `container:` images was not verified.

### Advisories

OSV lists three things against the locked versions. None of them comes with a newer release we could take:
- unsafe-libyaml 0.2.11 (RUSTSEC-2024-0449, unmaintained). It is an aprv-server build dependency and is not in the binary.
- Go stdlib entries against the `go` directives. The directive is a minimum, so these do not apply.
- The runtimes embed Wasmtime, and OSV has no entry for any of their package versions:
  - The Wasmtime NuGet package is at 48.0.2, which is still the newest on NuGet. OSV has 23 entries against the 48.0.2 crate, fixed in 48.0.3 to 48.0.8. Their reach is recorded in 38481aa3 and in the 2026-10-31 survey.
  - The wasmtime gem is at 50.0.0, which is the newest gem.

## What changed

- `.github/dependabot.yml`: the github-actions entry now has one group with `patterns: ["*"]` in place of `group-by: dependency-name`. A week's action updates, in the workflows and in the composite actions, arrive as one pull request, so the limit of five open pull requests cannot hold any back. The 7-day cooldown stays. This is in the pull request that adds this note.
- `rust/server/Cargo.toml`: `rust-version` is now 1.97.0. That is the highest `rust_version` crates.io lists among the 167 registry crates in `rust/server/Cargo.lock`, from `wasmtime` 50.0.1, its `wasmtime-*` and `pulley-*` sub-crates and `cranelift-*` 0.137.1. No CI job builds the server on 1.97.0, so the floor is stated, not tested. This is in the same pull request.
- The workflow pins with no updater moved in a separate pull request (branch `ci/manual-pins-2026-11`):
  - cbindgen 0.29.4, with the C header regenerated;
  - spectral-cli 6.17.0;
  - Gradle 9.8.2;
  - swift:6.3, and swift:6.4 at its 6.4.1 build;
  - the distroless java17, java21 and java25 debian13 images;
  - the four uv alpine images.

  Each new digest was pushed on or before 2026-10-28. eclipse-temurin and rustup stay where they were: the only newer digest and the only newer release (rustup 1.29.3, 2026-11-03) are inside the cooldown. That pull request also extends `tools/toolchain-watch.mjs` to every pin in this list, so a weekly issue reports them when they fall behind.

## Where this stops holding

- Maven was checked only for direct dependencies and plugins, as on 2026-10-31.
- Action dates are tag dates. Image dates are push or upload times. Neither is the moment a release was announced.
- The `open-pull-requests-limit` explanation is inferred from the pull request history.
- The Docker images were not scanned for CVEs.
- This is a snapshot of 2026-11-04. Rerun with a new cutoff.
