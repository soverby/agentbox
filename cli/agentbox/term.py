"""Terminal-safe text (PLAN §2.6): strings from the box, the gateway,
upstream servers, and logs are agent-controlled. Before they reach the
terminal, every C0 control (except tab, and newline where multi-line text is
intended), DEL, and C1 control (U+0080-U+009F, e.g. the one-byte CSI U+009B)
is shown as a visible `\\xNN` escape, so no escape sequence can retitle the
window, clear the screen, or forge output."""

from __future__ import annotations

import re

_CTRL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")
_CTRL_ML = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def clean(text: object, multiline: bool = False) -> str:
    s = str(text)
    return (_CTRL_ML if multiline else _CTRL).sub(lambda m: f"\\x{ord(m.group()):02x}", s)
