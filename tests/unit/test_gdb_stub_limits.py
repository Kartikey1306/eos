# SPDX-License-Identifier: MIT
# Copyright (c) 2026 EoS Project

"""The GDB stub's advertised limits are derived from its buffers, not typed.

qSupported used to report PacketSize=0x400 over a 512-byte receive buffer,
so every packet GDB was told it could send was refused; #158 derived the
advertised size from the buffer. The memory handlers had the same shape one
layer up: `m`/`M` refused `len > 128` while the packet could carry 248 bytes,
so a bulk transfer GDB sized from PacketSize was answered E01. The accept
path cannot run in tests/test_debug.c (the memory hooks dereference the
address), so the derivation is pinned here, in the source.
"""

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STUB = REPO_ROOT / "debug" / "src" / "gdb_stub.c"


def _text():
    text = STUB.read_text(encoding="utf-8")
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", " ", text)


def _define(text, name):
    m = re.search(r"^\s*#define\s+%s\s+(.+?)\s*$" % name, text, re.M)
    assert m, f"{name} is not defined in debug/src/gdb_stub.c"
    return m.group(1).strip()


def test_packet_max_is_derived_from_the_receive_buffer():
    text = _text()
    assert _define(text, "GDB_PKT_MAX") == "(GDB_PKT_BUF - 1)"
    assert re.search(r'PacketSize=%x[^"]*",\s*\(unsigned\)GDB_PKT_MAX', text), \
        "qSupported does not advertise GDB_PKT_MAX"


def test_memory_cap_is_derived_from_the_packet_max():
    text = _text()
    assert _define(text, "GDB_MEM_MAX") == "((GDB_PKT_MAX - GDB_MEM_HDR) / 2)"
    hdr = int(_define(text, "GDB_MEM_HDR"))
    assert hdr >= len("M") + 8 + len(",") + 4 + len(":"), "header allowance is below a 32-bit address and a 16-bit length"


def test_memory_handlers_use_the_derived_cap_and_no_literal():
    text = _text()
    for handler in ("handle_read_mem", "handle_write_mem"):
        body = text[text.index(f"static void {handler}"):]
        body = body[:body.index("\n}\n")]
        assert "len > GDB_MEM_MAX" in body, f"{handler} does not compare len against GDB_MEM_MAX"
        assert "buf[GDB_MEM_MAX]" in body, f"{handler} buffers are not sized by GDB_MEM_MAX"
        assert not re.search(r"\b128\b|\b256\b|\b257\b", body), f"{handler} still carries a literal size"


def test_reply_to_the_largest_read_fits_the_send_buffer():
    text = _text()
    pkt_buf = int(_define(text, "GDB_PKT_BUF"))
    hdr = int(_define(text, "GDB_MEM_HDR"))
    mem_max = ((pkt_buf - 1) - hdr) // 2
    m = re.search(r"char pkt\[(\d+)\];", text)
    assert m, "send_packet() buffer not found"
    assert mem_max * 2 + 4 < int(m.group(1)), "an m reply of GDB_MEM_MAX bytes would not fit send_packet()'s buffer"
