# platformdirs floor probes

| File | Question |
|---|---|
| `probe.py` | What does `user_cache_dir` answer for the package's cache, per platform class, with HOME set, XDG_CACHE_HOME absolute, relative, empty, and HOME empty, relative or unexpandable (`~nouser`)? |
| `nohome.py` | What does it answer when no home directory resolves at all? |

Reproduce (any POSIX machine with uv; nothing is written outside uv's own
cache):

```sh
cd "$REPO/docs/evidence/2026-10-04-python-platformdirs-floor"
for v in 4.5.1 4.6.0 4.11.7 4.11.8 4.11.15 4.12.0 4.12.3; do
  uv run -q --no-project --python 3.10 --with "platformdirs==$v" python probe.py
done
for v in 4.11.15 4.12.0; do
  uv run -q --no-project --python 3.10 --with "platformdirs==$v" python nohome.py
done
```

The `home-empty` row on 4.12.0 and later shows the password database's
home directory for whoever runs it.
