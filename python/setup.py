"""Build hooks only; the metadata is in pyproject.toml.

The one hook: building a wheel on, or for, a platform wasmtime-py has no
wheel for stops with a message that points to aprv-server and the C ABI
(docs/rust-core R28), instead of producing a package whose import fails.
``_wheel_platform`` explains the whole mechanism.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _wheel_platform
from setuptools import setup
from setuptools.command.bdist_wheel import bdist_wheel as _bdist_wheel
from setuptools.errors import PlatformError


class bdist_wheel(_bdist_wheel):
    def finalize_options(self) -> None:
        super().finalize_options()
        # The platform being built for: --plat-name when given (the release
        # builds one wheel per supported platform), else the build machine's.
        problem = _wheel_platform.unsupported_message(self.plat_name)
        if problem:
            raise PlatformError(problem)


setup(cmdclass={"bdist_wheel": bdist_wheel})
