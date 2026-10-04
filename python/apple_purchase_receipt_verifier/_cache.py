"""Wasmtime's on-disk compile cache, under the rules of THREAT-MODEL.md
section 8. The cache holds native code the next process runs, so a
directory anyone else can write would let them plant code:

1. the default is the running user's own cache directory, as
   ``platformdirs`` names it;
2. ``APRV_WASM_CACHE_DIR`` overrides the path (empty means: no cache);
3. the cache is off, silently, when the directory is read-only, cannot be
   created, is not owned by the running user, or is writable by group or
   others (a shared directory such as ``/tmp`` never holds it), or when the
   directory that contains it could be swapped by someone else.

Off is never an error: the process compiles ``aprv.wasm`` at start instead.
Where the platform has no owner or mode bits to read (Windows), only the
read-only rule applies.
"""

import contextlib
import os
import stat
import tempfile
from pathlib import Path

import platformdirs
import wasmtime

#: The environment variable that names the cache directory.
ENV_VAR = "APRV_WASM_CACHE_DIR"

_APP = "apple-purchase-receipt-verifier"


def _default_directory() -> "str | None":
    # appauthor=False and opinion=False keep Windows at
    # %LOCALAPPDATA%\<app>, without the <author>\<app>\Cache levels
    # platformdirs adds there by default; Linux and macOS ignore both.
    try:
        base = platformdirs.user_cache_dir(_APP, appauthor=False, opinion=False)
    except RuntimeError:  # no home directory to put it under
        return None
    return os.path.join(base, "wasmtime")


def _directory() -> "str | None":
    override = os.environ.get(ENV_VAR)
    if override is None:
        return _default_directory()
    return override if override and os.path.isabs(override) else None


def _mkdirs_private(path: str) -> None:
    """``os.makedirs`` with mode 0700 on every directory it creates, so the
    umask cannot leave a group-writable parent behind."""
    missing = []
    current = path
    while not os.path.isdir(current):
        missing.append(current)
        parent = os.path.dirname(current)
        if parent == current:
            break
        current = parent
    for directory in reversed(missing):
        with contextlib.suppress(FileExistsError):
            os.mkdir(directory, 0o700)


def _only_we_can_write(path: str, *, root_may_own: bool) -> bool:
    info = os.stat(path)
    if not stat.S_ISDIR(info.st_mode):
        return False
    owners = {os.geteuid()} | ({0} if root_may_own else set())
    if info.st_uid not in owners:
        return False
    if info.st_mode & 0o022:
        # Group- or world-writable is fine for the parent only when the
        # sticky bit stops others renaming what they do not own (/tmp).
        return root_may_own and bool(info.st_mode & stat.S_ISVTX)
    return True


def _acceptable(path: str) -> bool:
    if not os.access(path, os.W_OK | os.X_OK):
        return False
    if not hasattr(os, "geteuid"):
        return True
    real = os.path.realpath(path)
    return _only_we_can_write(real, root_may_own=False) and _only_we_can_write(
        os.path.dirname(real), root_may_own=True
    )


def usable_directory() -> "str | None":
    """The directory the cache may use, or ``None`` when it stays off."""
    try:
        path = _directory()
        if path is None:
            return None
        _mkdirs_private(path)
        return path if _acceptable(path) else None
    except OSError:
        return None


def enable(config: "wasmtime.Config") -> bool:
    """Turns ``config``'s cache on when the rules allow it; ``True`` if it
    is on. Wasmtime takes its cache directory from a TOML file, so one is
    written into the (already vetted) directory and removed again."""
    directory = usable_directory()
    if directory is None or any(c in directory for c in "'\r\n"):
        return False
    name = None
    try:
        descriptor, name = tempfile.mkstemp(suffix=".toml", dir=directory)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(f"[cache]\ndirectory = '{directory}'\n")
        config.cache = name
        return True
    except (OSError, wasmtime.WasmtimeError):
        return False
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)
