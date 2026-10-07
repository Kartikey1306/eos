# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""`eos clean` on Windows must not follow junctions out of build_dir (#178).

eos_rmtree_win32() recursed into every directory entry, so a junction or a
directory symlink inside build_dir made `eos clean` delete the files it
pointed at, outside the build directory. The function only compiles on
Windows and CI has no Windows C job, so the invariants are checked here, in
the source.
"""

import re
from pathlib import Path

MAIN = Path(__file__).resolve().parents[2] / "cmd" / "eos" / "main.c"


def _body():
    text = MAIN.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    start = text.index("static int eos_rmtree_win32(const char *path) {")
    depth, i = 0, text.index("{", start)
    for j in range(i, len(text)):
        depth += {"{": 1, "}": -1}.get(text[j], 0)
        if depth == 0:
            return text[start : j + 1]
    raise AssertionError("unbalanced braces in eos_rmtree_win32")


def test_reparse_points_are_checked_before_recursing():
    body = _body()
    reparse = body.index("FILE_ATTRIBUTE_REPARSE_POINT", body.index("FindFirstFileA"))
    recurse = body.index("eos_rmtree_win32(child)")
    assert reparse < recurse, "a child's reparse-point bit must be tested before recursing into it"


def test_a_reparse_point_is_unlinked_not_descended():
    body = _body()
    branch = re.search(r"if \(attrs & FILE_ATTRIBUTE_REPARSE_POINT\) \{(.*?)\}\s*else if", body, re.S)
    assert branch, "no reparse-point branch ahead of the directory branch"
    assert "eos_rmtree_win32" not in branch.group(1)
    assert "RemoveDirectoryA(child)" in branch.group(1)


def test_build_dir_that_is_itself_a_link_is_not_followed():
    body = _body()
    first_find = body.index("FindFirstFileA")
    assert "GetFileAttributesA(path)" in body[:first_find]
    assert "FILE_ATTRIBUTE_REPARSE_POINT" in body[:first_find]


def test_paths_are_never_silently_truncated():
    body = _body()
    # Every snprintf result is checked against the buffer size.
    calls = re.findall(r"(\w+)\s*=\s*snprintf\((\w+),", body)
    assert len(calls) == 2, calls
    for var, buf in calls:
        assert re.search(rf"\(size_t\){var}\s*>=\s*sizeof\({buf}\)", body), f"{buf} truncation unchecked"
