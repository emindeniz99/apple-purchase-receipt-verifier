# Dependency survey helpers (2026-11-04)

These back [../2026-11-04-dependency-survey.md](../2026-11-04-dependency-survey.md).
The survey itself reran the 2026-10-31 scripts
([../2026-10-31-dependency-survey/](../2026-10-31-dependency-survey/)); the
files here cover what those scripts do not.

| File | What it answers |
|---|---|
| `classify.py` | Splits each `newer.py` result at the cooldown cutoff (`$3`, default 2026-10-28): the newest release on or before it, and the releases after it. |
| `vlib.py` | Version ordering and the cutoff (`CUT`, default 2026-10-28) shared by the crate scripts. |
| `crates_fetch.py` | Caches every crates.io version, with its date and `rust_version`, for each crate in the `rust/` lockfiles, plus any names given as arguments. |
| `crates_direct.py` | For each direct dependency of each Cargo lockfile: the locked version, the newest release past the cutoff and its MSRV. `newer.py` keeps one version per crate across all lockfiles, which hides a lagging one. |
| `crates_trans.py` | Per Cargo lockfile: semver-compatible updates past the cutoff, ones still held, and crates with only incompatible releases. |
| `packagist.py` | Newest release in the locked major and overall, with each one's `require.php`. |
| `digest.py` | Whether a digest-pinned image tag has moved, and the image config's `created` for both digests. |
| `gcr.py` | The same for `gcr.io` images, with each digest's upload time from the tags list. |
| `msrv.py` | The highest `rust_version` crates.io lists among the registry crates of one Cargo lockfile (the aprv-server floor). Reads the `crates_fetch.py` cache. |
| `image_config.py` | For a digest: when the image was built, its user, its Java or Python version and its platforms. Used to choose the workflow image digests moved after the survey. |
| `tagdate.sh` | The tagger or commit date of a git tag, from a shallow blobless fetch, for when api.github.com is out of reach. |

## Reproduce

```sh
cd $SCRATCH
E=$REPO/docs/evidence
REPO=$REPO python3 -I $E/2026-10-31-dependency-survey/parse.py deps.json
CUT=0000-00-00 python3 -I $E/2026-10-31-dependency-survey/newer.py deps.json newer.json
python3 -I $E/2026-10-31-dependency-survey/osv.py deps.json osv.json
python3 -I $E/2026-11-04-dependency-survey/classify.py deps.json newer.json 2026-10-28
REPO=$REPO SCRATCH=$SCRATCH python3 -I $E/2026-11-04-dependency-survey/crates_fetch.py wasm-tools wit-bindgen-cli
REPO=$REPO SCRATCH=$SCRATCH python3 -I $E/2026-11-04-dependency-survey/crates_direct.py
REPO=$REPO SCRATCH=$SCRATCH python3 -I $E/2026-11-04-dependency-survey/crates_trans.py
python3 -I $E/2026-11-04-dependency-survey/packagist.py $REPO/php/composer.lock \
  symfony/process psr/clock friendsofphp/php-cs-fixer phpstan/phpstan phpunit/phpunit
python3 -I $E/2026-11-04-dependency-survey/digest.py \
  $(grep -rhoE '[a-z0-9./_-]+:[A-Za-z0-9._-]+@sha256:[0-9a-f]{64}' \
    $REPO/rust/server/Dockerfile $REPO/tools/reproduce/Dockerfile $REPO/.github/workflows/*.yml | sort -u)
python3 -I $E/2026-11-04-dependency-survey/gcr.py distroless/static-debian13,nonroot,<pinned digest>
python3 -I $E/2026-11-04-dependency-survey/msrv.py $REPO/rust/server/Cargo.lock $SCRATCH/cache/crates
python3 -I $E/2026-11-04-dependency-survey/image_config.py \
  gcr.io/distroless/java21-debian13@<digest> ghcr.io/astral-sh/uv@<digest> registry-1.docker.io/library/swift@<digest>
SCRATCH=$SCRATCH sh $E/2026-11-04-dependency-survey/tagdate.sh actions/setup-java v6.0.1 v6.1.0
```

`CUT=0000-00-00` makes `newer.py` list every newer release with its date, and
`classify.py` then splits that list at the cutoff. Behind a TLS-intercepting
proxy, set `SSL_CERT_FILE` to its CA bundle. Everything the scripts write
stays in `$SCRATCH`.
