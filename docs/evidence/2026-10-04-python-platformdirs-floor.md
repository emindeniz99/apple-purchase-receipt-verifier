# Python: the floor for platformdirs

**Question.** Which is the oldest platformdirs release whose
`user_cache_dir` names the compile cache's directory the same way every
newer release does, on Linux, macOS and Windows? It sets the floor in
`python/pyproject.toml` now that `_cache.py` takes the default directory
from platformdirs instead of computing it (owner decision, 2026-10-04).

**Versions.** platformdirs 4.5.1, 4.6.0, 4.11.7, 4.11.8, 4.11.15, 4.12.0
and 4.12.3 from PyPI, on CPython 3.10 (uv), 2026-10-04. The call is
`user_cache_dir("apple-purchase-receipt-verifier", appauthor=False,
opinion=False)`; the two keywords only matter on Windows, where they keep
the directory at `%LOCALAPPDATA%\apple-purchase-receipt-verifier` without
the `<author>\<app>\Cache` levels platformdirs adds by default.

**Method.** `probe.py` asks the Linux (`Unix`), macOS and Windows classes
directly, so one Linux machine answers for all three; Windows' known-folder
lookup is replaced with a fixed path. `nohome.py` removes HOME and the
password-database entry. Sources and commands are in
`2026-10-04-python-platformdirs-floor/`. The source at every tag from
4.5.0 to 4.12.3 (github.com/tox-dev/platformdirs) was searched for the
changes below, and the changelog checked.

## Results

From `probe.py` and `nohome.py` (`~` is the HOME the probe set):

| Case | 4.5.1 | 4.6.0, 4.11.7 | 4.11.8, 4.11.15 | 4.12.0, 4.12.3 |
|---|---|---|---|---|
| HOME set | `~/.cache/<app>` Linux, `~/Library/Caches/<app>` macOS | same | same | same |
| `XDG_CACHE_HOME=/x` | `/x/<app>` on Linux; ignored on macOS | `/x/<app>` on both | same | same |
| `XDG_CACHE_HOME=rel/x` | `rel/x/<app>` on Linux | `rel/x/<app>` on both | ignored: `~/.cache/<app>`, `~/Library/Caches/<app>` | same as 4.11.8 |
| `HOME=""` | `/.cache/<app>`, `/Library/Caches/<app>` | same | same | the password database's home |
| no home at all | `~/.cache/<app>`, unexpanded | same | same | `RuntimeError` |
| Windows | `<Local AppData>\<app>` (joined with `/` when the class runs on Linux) | same | same | same |

The changes line up with the changelog: macOS XDG support in 4.6.0
(tox-dev/platformdirs#375), relative XDG values ignored in 4.11.8 (#540),
an empty HOME read as unset and `RuntimeError` when no home resolves in
4.12.0 (#589). On Windows every release read asks the shell for the
Local AppData folder (`SHGetFolderPathW` in older releases,
`SHGetKnownFolderPath` in newer ones) rather than reading the
`LOCALAPPDATA` variable, so the cache's tests redirect it with
platformdirs' documented `WIN_PD_OVERRIDE_LOCAL_APPDATA` (4.8.0 and
later).

## Verdict

**Floor 4.12.0.** It is the oldest release that answers every case above
as the newest does, and every answer is either an absolute path or a
`RuntimeError`. So `_cache.py` drops its `os.path.isabs` guard on the
default directory (no release at or above the floor returns a relative
one) and turns the cache off on `RuntimeError` instead. Below the floor a
relative `XDG_CACHE_HOME` would become a cache directory relative to the
working directory, which is the case the guard existed for;
`tests/test_cache.py`'s relative-XDG test fails on 4.11.7.

4.12.0 was published on 2026-09-26, eight days before this note, so it
clears the seven-day cooldown; `python/uv.lock` locks it, not 4.12.3
(2026-10-03). It needs Python 3.10 or later, the package's own floor, and
has no dependencies of its own.

**Where this stops holding.** The Windows rows are platformdirs' own path
handling around a stubbed folder lookup; the real lookup runs only on the
CI's Windows legs. Android and iOS use other platformdirs classes that
were not probed.
