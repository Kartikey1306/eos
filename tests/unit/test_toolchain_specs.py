# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project
"""A -specs= file must reach the link line exactly once.

`arm-none-eabi-gcc` fails outright when the same spec file is supplied twice:

    fatal error: nosys.specs: attempt to rename spec 'link_gcc_c_sequence'
                 to already defined spec 'nosys_link_gcc_c_sequence'

CMake links through the compiler driver, so CMAKE_C_FLAGS_INIT reaches the
link line too -- naming a spec there *and* in CMAKE_EXE_LINKER_FLAGS_INIT
supplies it twice.

Nothing in CI would notice. Every ARM toolchain here sets
CMAKE_TRY_COMPILE_TARGET_TYPE to STATIC_LIBRARY and no cross build links an
executable, so `Cross-compile ARM Cortex-M4` passed identically with the
duplicate present and absent -- it passed on the unfixed commit. The defect
was found by accident, when a PR briefly put cmd/eos into the cross build.
This is the check that would have caught it, and it needs no ARM toolchain.

Modelled on tests/unit/test_cmake_test_registration.py: parse the build files
and fail on the class of mistake rather than on one instance of it.
"""

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TOOLCHAINS = REPO / "toolchains"

# Variables CMake puts on the link line. C/CXX flags get there because CMake
# links through the compiler driver.
LINK_REACHING = (
    "CMAKE_C_FLAGS_INIT",
    "CMAKE_CXX_FLAGS_INIT",
    "CMAKE_EXE_LINKER_FLAGS_INIT",
)

SET_RE = re.compile(r'set\(\s*(\w+)\s+"([^"]*)"', re.S)
SPECS_RE = re.compile(r'--?specs=(\S+)')


def _specs_per_variable(text):
    """{variable: [spec files]} for the variables that reach a link line."""
    found = {}
    for var, value in SET_RE.findall(text):
        if var in LINK_REACHING:
            specs = SPECS_RE.findall(value)
            if specs:
                found[var] = specs
    return found


def _toolchain_files():
    files = sorted(TOOLCHAINS.glob("*.cmake"))
    assert files, f"no toolchain files found under {TOOLCHAINS}"
    return files


def test_no_spec_file_reaches_the_link_line_twice():
    offenders = []
    for path in _toolchain_files():
        per_var = _specs_per_variable(path.read_text())
        seen = {}
        for var, specs in per_var.items():
            for spec in specs:
                seen.setdefault(spec, []).append(var)
        for spec, variables in seen.items():
            if len(variables) > 1:
                offenders.append(
                    f"{path.name}: -specs={spec} is set in "
                    f"{' and '.join(sorted(variables))}, so it reaches the "
                    f"link line more than once"
                )
    assert not offenders, (
        "arm-none-eabi-gcc rejects a duplicated spec file:\n  "
        + "\n  ".join(offenders)
    )


def test_specs_are_declared_on_the_linker_flags_not_the_compiler_flags():
    """Where a toolchain names a spec at all, it names it on the link line.

    Putting it in CMAKE_C_FLAGS_INIT happens to work today only because CMake
    links through the driver. It is the arrangement that turns into a
    duplicate the moment someone adds the linker entry that looks missing.
    """
    offenders = []
    for path in _toolchain_files():
        per_var = _specs_per_variable(path.read_text())
        for var in ("CMAKE_C_FLAGS_INIT", "CMAKE_CXX_FLAGS_INIT"):
            for spec in per_var.get(var, []):
                offenders.append(f"{path.name}: -specs={spec} is set in {var}")
    assert not offenders, (
        "declare spec files in CMAKE_EXE_LINKER_FLAGS_INIT:\n  "
        + "\n  ".join(offenders)
    )
