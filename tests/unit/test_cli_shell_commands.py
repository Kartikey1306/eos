# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project
"""The `eos` CLI builds every shell command through the checked builder.

`cmd_clean()` interpolated `workspace.build_dir` -- a value read from the
project's eos.yaml -- into `rm -rf "%s"` and handed it to system(), guarded by
a denylist of its own:

    if (strpbrk(build_dir, ";|&><$()\\"'"))

That list omits the backtick, and a shell performs command substitution inside
double quotes, so

    build_dir: /tmp/x`touch /tmp/marker`

passed the check and the substitution ran. It also omits the backslash and
control characters.

core/src/shell_cmd.c already exists for exactly this and refuses on the rule
services/linux/src/linux_security.c shipped. Its own unit test covers the
character rule (tests/test_shell_cmd.c); what this file pins is that the CLI
*uses* it -- that no shell command is assembled in main.c by hand again, which
is how the hole got there in the first place.
"""

import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
MAIN_C = ROOT / "cmd" / "eos" / "main.c"

# `system(` as a call, not `cmd_system(` -- the handler for the `eos system`
# subcommand, which is an ordinary function and not a shell at all.
BARE_SYSTEM_CALL = re.compile(r"(?<![A-Za-z0-9_])system\s*\(")

# The denylist idiom this replaced, in any spelling.
STRPBRK_CALL = re.compile(r"(?<![A-Za-z0-9_])strpbrk\s*\(")


def source() -> str:
    return MAIN_C.read_text(encoding="utf-8")


def code_lines():
    """(line number, line) with string literals and comments blanked out.

    The help text prints "Build hybrid system (Linux + RTOS)", and a scan of
    the raw file matches `system (` inside it. Searching prose for code is how
    a guard ends up asserting on its own explanatory text, so literals and
    comments are removed before anything is matched.
    """
    src = source()
    out, i, n = [], 0, len(src)
    in_str = in_chr = in_line_comment = in_block_comment = False
    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if in_line_comment:
            if c == "\n":
                in_line_comment = False
                out.append(c)
            else:
                out.append(" ")
        elif in_block_comment:
            if c == "*" and nxt == "/":
                in_block_comment = False
                out.append("  ")
                i += 2
                continue
            out.append("\n" if c == "\n" else " ")
        elif in_str or in_chr:
            if c == "\\":
                out.append("  ")
                i += 2
                continue
            if (in_str and c == '"') or (in_chr and c == "'"):
                in_str = in_chr = False
            out.append("\n" if c == "\n" else " ")
        else:
            if c == "/" and nxt == "/":
                in_line_comment = True
                out.append("  ")
                i += 2
                continue
            if c == "/" and nxt == "*":
                in_block_comment = True
                out.append("  ")
                i += 2
                continue
            if c == '"':
                in_str = True
                out.append(" ")
            elif c == "'":
                in_chr = True
                out.append(" ")
            else:
                out.append(c)
        i += 1
    return list(enumerate("".join(out).splitlines(), 1))


class CliShellCommandsGoThroughTheBuilder(unittest.TestCase):
    def test_main_c_exists(self):
        # A moved or renamed file would make every other assertion here vacuous.
        self.assertTrue(MAIN_C.is_file(), f"{MAIN_C} not found")

    def test_no_bare_system_call(self):
        hits = [
            f"{i}: {line.strip()}"
            for i, line in code_lines()
            if BARE_SYSTEM_CALL.search(line)
        ]
        self.assertEqual(
            hits,
            [],
            "shell commands in the CLI must be run through "
            "eos_shell_cmd_run(), not system():\n" + "\n".join(hits),
        )

    def test_no_handwritten_metacharacter_denylist(self):
        hits = [
            f"{i}: {line.strip()}"
            for i, line in code_lines()
            if STRPBRK_CALL.search(line)
        ]
        self.assertEqual(
            hits,
            [],
            "a denylist here is what missed the backtick; use "
            "eos_shell_cmd_arg(), which refuses on one reviewed rule:\n"
            + "\n".join(hits),
        )

    def test_clean_uses_the_builder(self):
        # Directional: the file must actually construct the clean command with
        # the builder, so that deleting the command entirely would not pass.
        src = source()
        self.assertIn('#include "eos/shell_cmd.h"', src)
        self.assertIn("eos_shell_cmd_init(&cmd);", src)
        self.assertIn("eos_shell_cmd_arg(&cmd, build_dir);", src)
        self.assertIn('eos_shell_cmd_run(&cmd, "Clean");', src)


if __name__ == "__main__":
    unittest.main()
