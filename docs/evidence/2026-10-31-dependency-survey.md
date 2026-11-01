# Dependency and advisory survey, 2026-10-31

**Question.** The survey asked three things:
- Which dependencies, across every package, have a release we don't take yet?
- Is any of those releases held only by the seven-day cooldown?
- Does any version we lock today carry a known advisory?

It decides what the 2026-10-31 maintenance pass takes now, what waits for the cooldown, and what gets a security exception.

## Method

The survey read the state that #463 brings, the catch-up of everything older than seven days.

1. `parse.py` read 1,216 locked or pinned versions:

   | Ecosystem | Versions |
   |---|---|
   | crates.io | 636 |
   | npm | 303 |
   | Packagist | 65 |
   | Maven | 64 |
   | NuGet | 62 |
   | RubyGems | 47 |
   | SwiftPM | 15 |
   | PyPI | 11 |
   | Go | 11 |

2. `newer.py` compared each against its registry, with 2026-10-24 as the cutoff.
3. `osv.py` sent 830 unique versions to OSV.
4. Actions tags were read with `git ls-remote`. Docker digests were read from the Docker Hub tags API.

The scripts are in [2026-10-31-dependency-survey/](./2026-10-31-dependency-survey/).

## Results

### Taken at once despite the cooldown

`pypa/gh-action-pypi-publish` v1.14.2 → v1.14.3 (#466). OSV lists versions before v1.14.3 as affected by GHSA-5xjx-3w67-w9x9, rated critical: the CA bundle the action ships includes a root that the advisory flags. The PyPI publish job runs this action. v1.14.3 was released on 2026-10-20, so it was already past the cooldown. Its diff from v1.14.2 is a hash-pinned requirements refresh.

### Fixed by the catch-up (#463)

- tokio 1.53.2 → 1.54.1 in aprv-server (RUSTSEC-2026-0386).
- setuptools 84.0.0 → 84.2.1, a dev dependency (GHSA-xmj3).

### Fixed by open dependabot PRs

- fast-uri 3.1.9 (#442; two moderate and two low advisories). It sits in tools/, and only the repository's own schema URIs pass through it.
- swift-crypto 5.0.3 (#458). Its changes look like security fixes, but OSV has no entry.

### Known and not reachable

| Version we lock | Advisory | Why it does not reach us |
|---|---|---|
| minimatch 10.2.6 (npm, build only, pinned exactly by jco-std) | GHSA-g3hv-75wg-m249, moderate | Its patterns are build-time constants. The fix is 11.0.1, which is inside the cooldown and has no 10.x backport. |
| Wasmtime 48.0.2 (NuGet, the newest there) | Advisories fixed in the 48.0.3 to 48.0.8 crates, GHSA-mghf-wjfp-p5xm among them | Each one needs a malicious guest module, the component model, GC or exceptions. The package runs only our module, pinned by SHA-256, and that is a plain core module. Which crate version the NuGet package embeds was not checked. |
| wasmtime gem 50.0.0 | RUSTSEC-2026-0422, 0423 and 0424, if the gem embeds the 50.0.0 crate | All three are GC or component-model only. |
| unsafe-libyaml 0.2.11 | RUSTSEC-2024-0449 (unmaintained) | It is a build dependency of aprv-server, reading `openapi.yaml`, and is not in the binary. |

### Held by the cooldown, no security fix

Shipped to consumers:
- endive 1.2.0 (the Java `-wasm` artifact, whose publishing is held)
- System.Text.Json 10.0.14
- symfony/process 7.4.22
- log, encoding_rs and rustix in aprv-server
- platformdirs 4.13.6 and later

.NET 10.0.14's CVEs (Brotli, tar) are in the runtime, not in the System.Text.Json package. About 40 dev and CI updates are also held, among them oxlint, jco, mypy, ruff, rubocop, phpstan, Actions and Docker digests. Nothing in the `aprv.wasm` dependency tree (`cargo tree` for wasm32-wasip1) has a release after the cutoff.

### Floors

platformdirs 4.13 needs Python 3.11. The 3.10 floor was the only thing holding it back, and the owner raised the floor (#464).

## Where this stops holding

- Maven was checked only for direct dependencies and plugins. Transitive dependencies were not resolved and BOMs were not expanded.
- The Docker images were not scanned for CVEs. The distroless, uv, mono and oss-fuzz image tags were not compared.
- The Go stdlib hits in OSV are against the `go` directive. That is a minimum, so they do not apply.
- This is a snapshot from 2026-10-31. Rerun the scripts with a new `CUT`.
