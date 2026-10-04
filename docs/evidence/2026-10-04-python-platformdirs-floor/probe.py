"""What platformdirs answers for the compile cache's directory, per platform
class and environment, in whichever platformdirs version runs this.

    uv run --no-project --python 3.10 --with platformdirs==4.12.0 python probe.py

The Linux and macOS classes compute paths without touching the system, so
they run anywhere. The Windows class asks the shell for the Local AppData
known folder; that call is replaced with a fixed answer, so its row shows
only what platformdirs appends to that folder.
"""

import os

import platformdirs
import platformdirs.windows as windows
from platformdirs.macos import MacOS
from platformdirs.unix import Unix

windows.get_win_folder = lambda name: "C:\\Users\\u\\AppData\\Local"  # type: ignore[assignment]

APP = "apple-purchase-receipt-verifier"
CASES = {
    "normal": {"HOME": "/h"},
    "xdg-abs": {"HOME": "/h", "XDG_CACHE_HOME": "/x"},
    "xdg-rel": {"HOME": "/h", "XDG_CACHE_HOME": "rel/x"},
    "xdg-empty": {"HOME": "/h", "XDG_CACHE_HOME": ""},
    "home-empty": {"HOME": ""},
    "home-rel": {"HOME": "relative"},
    "home-tilde": {"HOME": "~nouser"},
}


def answer(cls: type) -> str:
    try:
        return str(cls(APP, appauthor=False, opinion=False).user_cache_dir)
    except Exception as error:  # the row records what was raised
        return type(error).__name__


base = {k: v for k, v in os.environ.items() if k not in ("HOME", "XDG_CACHE_HOME")}
for name, env in CASES.items():
    os.environ.clear()
    os.environ.update(base)
    os.environ.update(env)
    print(
        f"{platformdirs.__version__:8} {name:10} linux={answer(Unix):45} "
        f"macos={answer(MacOS):45} windows={answer(windows.Windows)}"
    )
