"""What platformdirs answers when no home directory resolves: HOME unset and
no password-database entry for the user. POSIX only (it replaces pwd).

    uv run --no-project --python 3.10 --with platformdirs==4.12.0 python nohome.py
"""

import os
import pwd


def no_entry(uid: int) -> pwd.struct_passwd:
    raise KeyError(uid)


pwd.getpwuid = no_entry
os.environ.pop("HOME", None)
os.environ.pop("XDG_CACHE_HOME", None)

import platformdirs  # noqa: E402  (after the environment is set)
from platformdirs.macos import MacOS  # noqa: E402
from platformdirs.unix import Unix  # noqa: E402

for cls in (Unix, MacOS):
    try:
        result = repr(cls("app", appauthor=False, opinion=False).user_cache_dir)
    except Exception as error:  # the row records what was raised
        result = f"{type(error).__name__}: {error}"
    print(platformdirs.__version__, cls.__name__, result)
