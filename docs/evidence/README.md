# Evidence

Measurements and spikes behind decisions in the plans, threat model and
fixtures. Each one is a dated note, plus a folder of the same name when
there is code:

```
docs/evidence/
  2026-09-25-java-native-image.md      # the note: question, method, results, verdict
  2026-09-25-java-native-image-spike/  # the code that produced it
    README.md
```

A note without a folder is fine when nothing ran (a vendor document read,
an API probed by hand). A spike that ran code keeps that code here, including
spikes whose answer was "no". The rejected options are what stops the next
person from trying them again.

## The note

- The question, in one sentence, and what decision it feeds.
- Versions of every tool and library, and the date.
- Results with numbers. Name the file each number came from.
- Where the result stops holding (platform, version, input set).

## The folder

- A `README.md` with a table: each file or subfolder and the question it
  answered, then the commands to reproduce the results.
- `$REPO` for the repository root, `$SCRATCH` for any directory outside it.
  Every build output, download and result file goes to `$SCRATCH`.
- CI builds none of it. It is throwaway code, not the design.

## What stays out

- Binaries and build outputs: `.so`, `.jar`, `.wasm`, `target/`, archives.
  Record their size and hash in the note instead.
- Vendored or downloaded sources. Name the version and the URL.
- Lockfiles (`Cargo.lock`, `go.sum`, `package-lock.json` and the like).
  Nothing here ships, yet each pinned version was a Dependabot alert
  once an advisory reached it, and nobody bumps a spike. Name the
  versions that matter in the note instead; `.gitignore` here keeps the
  files out. To rerun a spike, resolve fresh versions first
  (`cargo generate-lockfile`, `go mod tidy`, `npm install`): a script
  that passes `--locked` fails without one. Removed 2026-11-03, after
  `wasmtime` 49.0.1 in two spike lockfiles raised a critical alert.
- Absolute local paths, usernames, host names, tokens and keys.
- Production receipts. Only the sandbox fixtures under `fixtures/` and
  receipts a spike generates from its own test PKI.

Check the folder before committing:

```sh
git status --short docs/evidence/
git diff --cached --stat
grep -rnE '/home/|/Users/|/root/|/tmp/' docs/evidence/<folder>/
```
