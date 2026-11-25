"""Unicode character tables and classification helpers for invisi_guard.

The core package is intentionally dependency-free (Python standard library only).
Offsets used everywhere in this project are Python ``str`` indices, i.e. Unicode
code point offsets -- not UTF-16 code units and not UTF-8 byte offsets.

Sources for the character classes:
  * Unicode Standard, chapter 23 (Bidirectional Controls, Zero Width Characters,
    Variation Selectors, Tags block U+E0000..U+E007F).
  * Trojan Source (CVE-2021-42574), https://trojansource.codes/
  * Public ASCII-smuggling reporting (Tags block), see docs/THREAT_MODEL.md.
"""

from __future__ import annotations

import unicodedata

__all__ = [
    "BIDI_ALL",
    "BIDI_EMBEDDINGS",
    "BIDI_ISOLATES",
    "BIDI_MARKS",
    "BIDI_OVERRIDES",
    "BIDI_TERMINATORS",
    "ZERO_WIDTH",
    "ZW_BIT_CHARS",
    "HOMOGLYPHS",
    "TAG_ASCII_HIGH",
    "TAG_ASCII_LOW",
    "TAG_CANCEL",
    "TAG_LANGUAGE",
    "TAG_MAX",
    "TAG_MIN",
    "bidi_name",
    "is_bidi_control",
    "is_emoji_base",
    "is_indic_like",
    "is_tag",
    "is_variation_selector",
    "is_zero_width",
    "script_of",
    "tag_to_ascii",
    "variation_selector_index",
    "unicode_name",
]

VERSION = "0.1.0"
TOOL = "invisi-guard"

# ---------------------------------------------------------------------------
# Bidirectional control characters
# ---------------------------------------------------------------------------
# Trojan Source abuses bidirectionality: U+202A..U+202E (embeddings/override +
# PDF terminator) and U+2066..U+2069 (directional isolates). U+200E/U+200F are
# the lightweight directional marks and are common in legitimate RTL text.
BIDI_EMBEDDINGS = {0x202A: "LRE", 0x202B: "RLE"}
BIDI_OVERRIDES = {0x202D: "LRO", 0x202E: "RLO"}
BIDI_TERMINATORS = {0x202C: "PDF"}
BIDI_ISOLATES = {0x2066: "LRI", 0x2067: "RLI", 0x2068: "FSI", 0x2069: "PDI"}
BIDI_MARKS = {0x200E: "LRM", 0x200F: "RLM", 0x061C: "ALM"}
BIDI_ALL = {}
BIDI_ALL.update(BIDI_EMBEDDINGS)
BIDI_ALL.update(BIDI_OVERRIDES)
BIDI_ALL.update(BIDI_TERMINATORS)
BIDI_ALL.update(BIDI_ISOLATES)
BIDI_ALL.update(BIDI_MARKS)


def is_bidi_control(ch: str) -> bool:
    """True when ``ch`` is one of the tracked bidirectional control characters."""
    return len(ch) == 1 and ord(ch) in BIDI_ALL


def bidi_name(ch: str) -> str | None:
    return BIDI_ALL.get(ord(ch)) if len(ch) == 1 else None


# ---------------------------------------------------------------------------
# Zero-width and invisible formatting characters
# ---------------------------------------------------------------------------
ZERO_WIDTH = {
    0x200B: "ZWSP",  # ZERO WIDTH SPACE
    0x200C: "ZWNJ",  # ZERO WIDTH NON-JOINER
    0x200D: "ZWJ",  # ZERO WIDTH JOINER
    0x2060: "WJ",  # WORD JOINER
    0x2061: "FA",  # FUNCTION APPLICATION (invisible operator)
    0x2062: "IT",  # INVISIBLE TIMES
    0x2063: "IS",  # INVISIBLE SEPARATOR
    0x2064: "IP",  # INVISIBLE PLUS
    0xFEFF: "ZWNBSP",  # ZERO WIDTH NO-BREAK SPACE / BOM
    0x180E: "MVS",  # MONGOLIAN VOWEL SEPARATOR (classic zero-width)
    0x034F: "CGJ",  # COMBINING GRAPHEME JOINER
}

# Characters commonly used as the two symbols of a binary payload, plus ZWJ as
# an alternate "1" bit or terminator in variants of the scheme.
ZW_BIT_CHARS = frozenset({0x200B, 0x200C, 0x200D})


def is_zero_width(ch: str) -> bool:
    return len(ch) == 1 and ord(ch) in ZERO_WIDTH


# ---------------------------------------------------------------------------
# Unicode Tags block: U+E0000..U+E007F
# ---------------------------------------------------------------------------
TAG_MIN = 0xE0000
TAG_MAX = 0xE007F
TAG_LANGUAGE = 0xE0001  # deprecated LANGUAGE TAG
TAG_ASCII_LOW = 0xE0020  # encode ASCII 0x20 (space)
TAG_ASCII_HIGH = 0xE007E  # encode ASCII 0x7E (~)
TAG_CANCEL = 0xE007F


def is_tag(ch: str) -> bool:
    return len(ch) == 1 and TAG_MIN <= ord(ch) <= TAG_MAX


def tag_to_ascii(ch: str) -> str | None:
    """Map a Tags-block character back to the ASCII character it mirrors."""
    cp = ord(ch)
    if TAG_ASCII_LOW <= cp <= TAG_ASCII_HIGH:
        return chr(cp - TAG_MIN)
    return None


# ---------------------------------------------------------------------------
# Variation selectors
# ---------------------------------------------------------------------------
VS_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


def is_variation_selector(ch: str) -> bool:
    if len(ch) != 1:
        return False
    cp = ord(ch)
    return (0xFE00 <= cp <= 0xFE0F) or (0xE0100 <= cp <= 0xE01EF)


def variation_selector_index(ch: str) -> int:
    """Return a 0-based index for a variation selector (0..15 or 0..239)."""
    cp = ord(ch)
    if 0xFE00 <= cp <= 0xFE0F:
        return cp - 0xFE00
    if 0xE0100 <= cp <= 0xE01EF:
        return cp - 0xE0100
    raise ValueError("not a variation selector: U+%04X" % cp)


# ---------------------------------------------------------------------------
# Emoji plausibility (used only to avoid flagging legitimate emoji sequences)
# ---------------------------------------------------------------------------
# Broad, deliberately conservative ranges of characters that can carry
# emoji-presentation variation selectors or participate in ZWJ sequences.
EMOJI_RANGES = (
    (0x00A9, 0x00A9),
    (0x00AE, 0x00AE),
    (0x203C, 0x203C),
    (0x2049, 0x2049),
    (0x2122, 0x2122),
    (0x2139, 0x2139),
    (0x2194, 0x21AA),
    (0x2300, 0x23FF),
    (0x25A0, 0x27BF),
    (0x2934, 0x2935),
    (0x2B00, 0x2BFF),
    (0x3030, 0x3030),
    (0x303D, 0x303D),
    (0x3297, 0x3299),
    (0x1F000, 0x1F1FF),
    (0x1F200, 0x1FAFF),
)


def is_emoji_base(ch: str) -> bool:
    """Heuristic: could this character be an emoji presentation base?

    This is only used to keep *legitimate* emoji sequences (ZWJ families,
    FE0F presentation selectors, subdivision flags) out of the scanner's
    attack findings. False positives here only reduce sensitivity for a
    character that already needs to be part of an emoji sequence to matter.
    """
    if len(ch) != 1:
        return False
    cp = ord(ch)
    for low, high in EMOJI_RANGES:
        if low <= cp <= high:
            return True
    return False


# ---------------------------------------------------------------------------
# Script detection (for mixed-script / homoglyph findings)
# ---------------------------------------------------------------------------
_SCRIPT_PREFIXES = (
    ("LATIN", "LATIN"),
    ("GREEK", "GREEK"),
    ("CYRILLIC", "CYRILLIC"),
    ("ARMENIAN", "ARMENIAN"),
    ("HEBREW", "HEBREW"),
    ("ARABIC", "ARABIC"),
    ("DEVANAGARI", "DEVANAGARI"),
    ("BENGALI", "BENGALI"),
    ("GURMUKHI", "GURMUKHI"),
    ("GUJARATI", "GUJARATI"),
    ("ORIYA", "ORIYA"),
    ("TAMIL", "TAMIL"),
    ("TELUGU", "TELUGU"),
    ("KANNADA", "KANNADA"),
    ("MALAYALAM", "MALAYALAM"),
    ("SINHALA", "SINHALA"),
    ("THAI", "THAI"),
    ("LAO", "LAO"),
    ("TIBETAN", "TIBETAN"),
    ("MYANMAR", "MYANMAR"),
    ("GEORGIAN", "GEORGIAN"),
    ("ETHIOPIC", "ETHIOPIC"),
    ("CHEROKEE", "CHEROKEE"),
    ("HIRAGANA", "HIRAGANA"),
    ("KATAKANA", "KATAKANA"),
    ("HANGUL", "HANGUL"),
)

_script_cache: dict[str, str | None] = {}


def script_of(ch: str) -> str | None:
    """Best-effort Unicode script name (e.g. ``LATIN``, ``CYRILLIC``).

    Returns ``None`` for digits, punctuation, symbols and unassigned characters.
    CJK Unified Ideographs are reported as ``CJK``; the CJK family (Han,
    Hiragana, Katakana, Hangul) is treated as one group by the scanner because
    Japanese and Korean legitimately mix those scripts inside a single word.
    """
    if len(ch) != 1:
        return None
    cached = _script_cache.get(ch)
    if cached is not None or ch in _script_cache:
        return cached
    result: str | None = None
    try:
        name = unicodedata.name(ch)
    except ValueError:
        name = ""
    if name:
        if name.startswith("CJK") or "IDEOGRAPH" in name:
            result = "CJK"
        else:
            for prefix, script in _SCRIPT_PREFIXES:
                if name.startswith(prefix):
                    result = script
                    break
    _script_cache[ch] = result
    return result


def is_indic_like(script: str | None) -> bool:
    """Scripts whose legitimate typography uses ZWJ/ZWNJ between letters."""
    return script in {
        "DEVANAGARI",
        "BENGALI",
        "GURMUKHI",
        "GUJARATI",
        "ORIYA",
        "TAMIL",
        "TELUGU",
        "KANNADA",
        "MALAYALAM",
        "SINHALA",
        "KHMER",
        "MYANMAR",
        "ARABIC",
    }


# ---------------------------------------------------------------------------
# Homoglyph / confusable map (Cyrillic and Greek -> Latin look-alikes)
# ---------------------------------------------------------------------------
# This is a curated subset of the Unicode "confusables" data, restricted to
# characters that appear in real spoofing of Latin words. It is intentionally
# small and auditable rather than exhaustive.
HOMOGLYPHS: dict[int, tuple[str, str]] = {
    # Cyrillic lowercase
    0x0430: ("a", "CYRILLIC SMALL LETTER A"),
    0x0435: ("e", "CYRILLIC SMALL LETTER IE"),
    0x043E: ("o", "CYRILLIC SMALL LETTER O"),
    0x0440: ("p", "CYRILLIC SMALL LETTER ER"),
    0x0441: ("c", "CYRILLIC SMALL LETTER ES"),
    0x0443: ("y", "CYRILLIC SMALL LETTER U"),
    0x0445: ("x", "CYRILLIC SMALL LETTER HA"),
    0x0455: ("s", "CYRILLIC SMALL LETTER DZE"),
    0x0456: ("i", "CYRILLIC SMALL LETTER BYELORUSSIAN-UKRAINIAN I"),
    0x0458: ("j", "CYRILLIC SMALL LETTER JE"),
    0x04BB: ("h", "CYRILLIC SMALL LETTER SHHA"),
    0x04CF: ("l", "CYRILLIC SMALL LETTER PALOCHKA"),
    0x0501: ("d", "CYRILLIC SMALL LETTER KOMI DE"),
    0x051B: ("q", "CYRILLIC SMALL LETTER QA"),
    0x051D: ("w", "CYRILLIC SMALL LETTER WE"),
    0x04AF: ("y", "CYRILLIC SMALL LETTER STRAIGHT U"),
    # Cyrillic uppercase
    0x0410: ("A", "CYRILLIC CAPITAL LETTER A"),
    0x0412: ("B", "CYRILLIC CAPITAL LETTER VE"),
    0x0415: ("E", "CYRILLIC CAPITAL LETTER IE"),
    0x041A: ("K", "CYRILLIC CAPITAL LETTER KA"),
    0x041C: ("M", "CYRILLIC CAPITAL LETTER EM"),
    0x041D: ("H", "CYRILLIC CAPITAL LETTER EN"),
    0x041E: ("O", "CYRILLIC CAPITAL LETTER O"),
    0x0420: ("P", "CYRILLIC CAPITAL LETTER ER"),
    0x0421: ("C", "CYRILLIC CAPITAL LETTER ES"),
    0x0422: ("T", "CYRILLIC CAPITAL LETTER TE"),
    0x0425: ("X", "CYRILLIC CAPITAL LETTER HA"),
    0x0423: ("Y", "CYRILLIC CAPITAL LETTER U"),
    0x0405: ("S", "CYRILLIC CAPITAL LETTER DZE"),
    0x0406: ("I", "CYRILLIC CAPITAL LETTER BYELORUSSIAN-UKRAINIAN I"),
    0x0408: ("J", "CYRILLIC CAPITAL LETTER JE"),
    0x04C0: ("I", "CYRILLIC CAPITAL LETTER PALOCHKA"),
    # Greek lowercase
    0x03B1: ("a", "GREEK SMALL LETTER ALPHA"),
    0x03B5: ("e", "GREEK SMALL LETTER EPSILON"),
    0x03B9: ("i", "GREEK SMALL LETTER IOTA"),
    0x03BA: ("k", "GREEK SMALL LETTER KAPPA"),
    0x03BD: ("v", "GREEK SMALL LETTER NU"),
    0x03BF: ("o", "GREEK SMALL LETTER OMICRON"),
    0x03C1: ("p", "GREEK SMALL LETTER RHO"),
    0x03C4: ("t", "GREEK SMALL LETTER TAU"),
    0x03C5: ("u", "GREEK SMALL LETTER UPSILON"),
    0x03C7: ("x", "GREEK SMALL LETTER CHI"),
    0x03B3: ("y", "GREEK SMALL LETTER GAMMA"),
    # Greek uppercase
    0x0391: ("A", "GREEK CAPITAL LETTER ALPHA"),
    0x0392: ("B", "GREEK CAPITAL LETTER BETA"),
    0x0395: ("E", "GREEK CAPITAL LETTER EPSILON"),
    0x0396: ("Z", "GREEK CAPITAL LETTER ZETA"),
    0x0397: ("H", "GREEK CAPITAL LETTER ETA"),
    0x0399: ("I", "GREEK CAPITAL LETTER IOTA"),
    0x039A: ("K", "GREEK CAPITAL LETTER KAPPA"),
    0x039C: ("M", "GREEK CAPITAL LETTER MU"),
    0x039D: ("N", "GREEK CAPITAL LETTER NU"),
    0x039F: ("O", "GREEK CAPITAL LETTER OMICRON"),
    0x03A1: ("P", "GREEK CAPITAL LETTER RHO"),
    0x03A4: ("T", "GREEK CAPITAL LETTER TAU"),
    0x03A5: ("Y", "GREEK CAPITAL LETTER UPSILON"),
    0x03A7: ("X", "GREEK CAPITAL LETTER CHI"),
    0x03F9: ("C", "GREEK CAPITAL LUNATE SIGMA SYMBOL"),
    0x03F2: ("c", "GREEK LUNATE SIGMA SYMBOL"),
}


def unicode_name(ch: str) -> str:
    """``unicodedata.name`` with a stable placeholder for unnamed characters."""
    try:
        return unicodedata.name(ch)
    except ValueError:
        return "UNNAMED U+%04X" % ord(ch)
