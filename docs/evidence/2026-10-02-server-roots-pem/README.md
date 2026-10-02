# 2026-10-02 server-roots-pem harness

| Path | Question it answered |
|---|---|
| `src/old.rs` | `Roots::from_file_text` from `rust/server/src/roots.rs` at the base commit, with its hand-written PEM block reader. |
| `src/new.rs` | The same function with the `pem` crate reading each block, as committed. |
| `src/main.rs` | Reads each file named on the command line with both and reports whether they agree: the same DER list, or both refusing. Exits 1 on a disagreement. |
| `make-inputs.sh` | Writes the 29 roots files the harness reads, from `certs/` and `fixtures/apple-official/certs/`. |

Both readers return the DER list instead of `Roots::Configured`; nothing
else differs from the server's source.

## Reproduce

Base commit: `e0016b1`. `$REPO` is the repository root, `$SCRATCH` any
directory outside it.

```sh
sh "$REPO/docs/evidence/2026-10-02-server-roots-pem/make-inputs.sh" "$SCRATCH/in"   # from $REPO
cargo run --manifest-path "$REPO/docs/evidence/2026-10-02-server-roots-pem/Cargo.toml" \
  --target-dir "$SCRATCH/target" -- "$SCRATCH"/in/*
```

The last line printed is `same 29, diff 0`.
