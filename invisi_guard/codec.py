"""Encoders for the three invisible-Unicode payload schemes, used by tests and demos.

These are deliberately simple reference encoders so that the decoder can be
tested against known-good round trips. They are *not* meant to be stealthy.
"""

from __future__ import annotations

from .chars import TAG_CANCEL

__all__ = [
    "encode_tag_ascii",
    "encode_variation_selectors_bytes",
    "encode_variation_selectors_hex",
    "encode_zero_width_binary",
]

_ZW_ZERO = "\u200b"
_ZW_ONE = "\u200c"


def _to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for byte in data:
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)
    return bits


def encode_zero_width_binary(
    text: str,
    *,
    one: str = _ZW_ONE,
    bit_order: str = "msb",
) -> str:
    """Encode text as U+200B/one-character bits (zero-width binary scheme).

    ``one`` may be ``"\\u200c"`` (ZWNJ) or ``"\\u200d"`` (ZWJ); the decoder
    supports both. ``bit_order`` is ``"msb"`` or ``"lsb"``.
    """
    if bit_order == "msb":
        bits = _to_bits(text.encode("utf-8"))
    elif bit_order == "lsb":
        bits = []
        for byte in text.encode("utf-8"):
            for shift in range(8):
                bits.append((byte >> shift) & 1)
    else:
        raise ValueError("bit_order must be 'msb' or 'lsb'")
    if one not in ("\u200c", "\u200d"):
        raise ValueError("one must be '\\u200c' or '\\u200d'")
    return "".join(one if bit else _ZW_ZERO for bit in bits)


def encode_tag_ascii(text: str, *, cancel: bool = True) -> str:
    """Encode printable ASCII as Unicode Tags-block characters (ASCII smuggling)."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if not 0x20 <= cp <= 0x7E:
            raise ValueError("tag scheme only encodes printable ASCII, got %r" % ch)
        out.append(chr(0xE0000 + cp))
    if cancel:
        out.append(chr(TAG_CANCEL))
    return "".join(out)


def encode_variation_selectors_hex(text: str) -> str:
    """Encode ASCII text as pairs of variation selectors U+FE00..U+FE0F (hex digits)."""
    data = text.encode("ascii")
    out: list[str] = []
    for byte in data:
        out.append(chr(0xFE00 + (byte >> 4)))
        out.append(chr(0xFE00 + (byte & 0x0F)))
    return "".join(out)


def encode_variation_selectors_bytes(text: str) -> str:
    """Encode ASCII text as one variation selector per byte (U+E0100 + value)."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if not 0x00 <= cp <= 0xEF:
            raise ValueError("vs-byte scheme supports byte values 0..239 only")
        out.append(chr(0xE0100 + cp))
    return "".join(out)
