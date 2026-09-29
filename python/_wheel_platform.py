"""Which platforms this package installs on, for setup.py (a build-time file,
not part of the wheel).

The package runs its verification core as WebAssembly on wasmtime-py, and
wasmtime-py ships wheels for Linux (glibc and musl) on x86_64 and aarch64,
macOS on x86_64 and arm64, Windows on x86_64 and arm64, and Android. Anywhere
else pip falls back to wasmtime-py's ``py3-none-any`` wheel, which holds only
the Windows x86_64 library, and ``import wasmtime`` fails later, at run time.
R28 of docs/rust-core moves that failure to install time:

* the release publishes this package as one wheel per supported platform and
  no ``py3-none-any`` wheel (``tools/build_dist.py``), so on any other
  platform pip finds no wheel and builds the sdist;
* building anything from this source tree, the sdist included, refuses an
  unsupported platform (``setup.py`` calls :func:`unsupported_message`), so
  that build stops with a message pointing to ``aprv-server`` and the C ABI.

``sysconfig.get_platform()`` is what pip itself derives its wheel tags from,
so the check and pip's choice agree, and ``_PYTHON_HOST_PLATFORM`` overrides
it for both, which is how the install-failure test simulates a platform.
"""

import re

#: The wheels the release publishes, one per platform wasmtime-py has a
#: wheel for (Android is covered by the check but not published: PyPI takes
#: no Android wheels yet, and an Android install builds the sdist).
WHEEL_TAGS = (
    "manylinux2014_x86_64",
    "manylinux2014_aarch64",
    "musllinux_1_2_x86_64",
    "musllinux_1_2_aarch64",
    "macosx_10_13_x86_64",
    "macosx_11_0_arm64",
    "win_amd64",
    "win_arm64",
)

_SUPPORTED = (
    # Linux, either libc: the plain tag distutils reports, or a wheel tag.
    re.compile(r"^(linux|manylinux(1|2010|2014|_\d+_\d+)|musllinux_\d+_\d+)_(x86_64|aarch64)$"),
    # macOS: any deployment target, on the two architectures (or both).
    re.compile(r"^macosx_\d+_\d+_(x86_64|arm64|universal2)$"),
    re.compile(r"^win_(amd64|arm64)$"),
    re.compile(r"^android_\d+_(arm64_v8a|x86_64)$"),
)

_NAME = "apple-purchase-receipt-verifier"


def normalize(platform: str) -> str:
    """``linux-x86_64`` and ``linux_x86_64`` are one platform; so are the
    ``.`` and ``-`` spellings of a macOS version."""
    return re.sub(r"[-. ]", "_", platform.strip().lower())


def is_supported(platform: str) -> bool:
    name = normalize(platform)
    return any(pattern.match(name) for pattern in _SUPPORTED)


def unsupported_message(platform: str) -> "str | None":
    """The install failure for ``platform``, or ``None`` where the package
    installs."""
    if is_supported(platform):
        return None
    return (
        f"{_NAME} cannot be installed on this platform ({platform}).\n"
        "It runs its verification core as WebAssembly on wasmtime-py, which publishes wheels\n"
        "only for Linux (glibc and musl) x86_64 and aarch64, macOS x86_64 and arm64, Windows\n"
        "x86_64 and arm64, and Android; here it would install without a usable runtime and\n"
        "fail at import.\n"
        "Use aprv-server instead (one static binary or a Docker image; call it over HTTP or its\n"
        "command line from any language), or the C ABI (rust/ffi, built from source). See\n"
        "https://github.com/emindeniz99/apple-purchase-receipt-verifier"
    )
