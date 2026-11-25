"""invisi_guard core: scan, decode and sanitize invisible-Unicode prompt injection.

The package is standard-library only. Everything here is deterministic: no
network access, no randomness, no clock/timezone dependence, no locale
dependence in the output ordering.

Threat classes covered (each finding carries a stable ``code`` and a severity):

* Bidirectional control characters (Trojan Source family, CVE-2021-42574):
  U+202A..U+202E and U+2066..U+2069, plus the directional marks
  U+200E/U+200F/U+061C.
* Zero-width characters U+200B..U+200D, U+2060..U+2064, U+FEFF, U+180E, U+034F,
  including binary payloads encoded with zero-width space / non-joiner / joiner.
* Unicode Tags block U+E0000..U+E007F ("ASCII smuggling"): tag characters mirror
  ASCII U+0020..U+007E invisibly. Legitimate emoji subdivision flags
  (U+1F3F4 + tag letters + U+E007F) are classified as benign.
* Variation selectors U+FE00..U+FE0F and U+E0100..U+E01EF, including the
  hex-nibble and byte payload schemes used to hide text after emoji/letters.
* Mixed-script tokens and Cyrillic/Greek homoglyphs that impersonate Latin.

Severity model
--------------
``high``   Hidden instruction/payload is decodable, or a control sequence has
           no plausible benign explanation (RLO/LRO overrides, Tags block,
           zero-width/VS payload runs, Latin+Cyrillic token mixing).
``medium`` Weird but not necessarily hostile: single bidi embedding/isolate,
           short zero-width or variation-selector runs, non-Latin mixed scripts.
``low``    Informational: isolated directional marks, a single stray invisible
           character outside a payload run, benign tagging conventions.

Offsets in findings are Python string indices (Unicode code points). Lines and
columns are 1-based; columns count code points.
"""

from __future__ import annotations

import bisect
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Any

from .chars import (
    BIDI_ALL,
    BIDI_EMBEDDINGS,
    BIDI_ISOLATES,
    BIDI_OVERRIDES,
    BIDI_TERMINATORS,
    HOMOGLYPHS,
    TAG_CANCEL,
    TOOL,
    VERSION,
    ZERO_WIDTH,
    is_bidi_control,
    is_emoji_base,
    is_indic_like,
    is_tag,
    is_variation_selector,
    is_zero_width,
    script_of,
    tag_to_ascii,
    variation_selector_index,
)

__all__ = [
    "Finding",
    "Payload",
    "SEVERITIES",
    "SEVERITY_RANK",
    "scan",
    "decode",
    "clean",
    "escape_visible",
    "summarize",
    "max_severity",
    "findings_to_dicts",
]

SEVERITIES = ("low", "medium", "high")
SEVERITY_RANK = {name: rank for rank, name in enumerate(SEVERITIES, start=1)}
MAX_DECODED_PREVIEW = 160


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Finding:
    """One deterministic scanner finding."""

    code: str
    kind: str
    severity: str
    start: int
    end: int
    line: int
    column: int
    message: str
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_RANK:
            raise ValueError("invalid severity: %r" % (self.severity,))
        if not (0 <= self.start <= self.end):
            raise ValueError("invalid span: %r" % ((self.start, self.end),))

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "kind": self.kind,
            "severity": self.severity,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "data": self.data,
        }


@dataclass(frozen=True)
class Payload:
    """A hidden payload recovered from invisible characters."""

    scheme: str
    start: int
    end: int
    decoded: str
    confidence: float
    data: dict[str, Any] = field(default_factory=dict)

    @property
    def length(self) -> int:
        return self.end - self.start

    def to_dict(self) -> dict[str, Any]:
        return {
            "scheme": self.scheme,
            "start": self.start,
            "end": self.end,
            "length": self.length,
            "decoded": self.decoded,
            "confidence": self.confidence,
            "data": self.data,
        }


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def _line_starts(text: str) -> list[int]:
    starts = [0]
    for match in re.finditer("\n", text):
        starts.append(match.end())
    return starts


def _line_col(line_starts: list[int], index: int) -> tuple[int, int]:
    line_index = bisect.bisect_right(line_starts, index) - 1
    if line_index < 0:
        line_index = 0
    return line_index + 1, index - line_starts[line_index] + 1


def escape_visible(text: str, *, limit: int | None = None) -> str:
    """Escape non-printable/invisible characters so output is terminal-safe."""
    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if ch == "\\":
            out.append("\\\\")
        elif ch in "\n\r\t":
            out.append({"\n": "\\n", "\r": "\\r", "\t": "\\t"}[ch])
        elif 0x20 <= cp <= 0x7E:
            out.append(ch)
        elif cp <= 0xFFFF:
            out.append("\\u%04X" % cp)
        else:
            out.append("\\U%08X" % cp)
        if limit is not None and len(out) >= limit:
            out.append("...")
            break
    return "".join(out)


def _preview(decoded: str) -> str:
    escaped = escape_visible(decoded)
    if len(escaped) > MAX_DECODED_PREVIEW:
        return escaped[:MAX_DECODED_PREVIEW] + "..."
    return escaped


def _is_bom_position(text: str, index: int) -> bool:
    return index == 0 and text.startswith("\ufeff")


def _emoji_side(text: str, index: int, step: int) -> bool:
    """Check for an emoji base adjacent to a joiner, skipping variation selectors."""
    k = index
    while 0 <= k < len(text) and is_variation_selector(text[k]):
        k += step
    return 0 <= k < len(text) and is_emoji_base(text[k])


def _joiner_context_ok(text: str, index: int) -> bool:
    """True when a ZWJ/ZWNJ is plausibly used for legitimate typography/emoji."""
    ch = text[index]
    prev_char = text[index - 1] if index > 0 else ""
    next_char = text[index + 1] if index + 1 < len(text) else ""
    if ch == "\u200d":  # ZWJ
        if _emoji_side(text, index - 1, -1) and _emoji_side(text, index + 1, 1):
            return True
        prev_script = script_of(prev_char) if prev_char else None
        next_script = script_of(next_char) if next_char else None
        if prev_script and prev_script == next_script and is_indic_like(prev_script):
            return True
        return False
    if ch == "\u200c":  # ZWNJ
        prev_script = script_of(prev_char) if prev_char else None
        next_script = script_of(next_char) if next_char else None
        if prev_script and prev_script == next_script and is_indic_like(prev_script):
            return True
        return False
    return False


def _variation_selector_context_ok(text: str, index: int) -> bool:
    """A single variation selector after a letter/emoji is treated as presentation."""
    if index == 0:
        return False
    prev_char = text[index - 1]
    if is_emoji_base(prev_char):
        return True
    # Keycap sequences: [#*0-9] + VS16 + U+20E3 (COMBINING ENCLOSING KEYCAP).
    if index + 1 < len(text) and text[index + 1] == "\u20e3" and prev_char in "0123456789#*":
        return True
    category = unicodedata.category(prev_char)
    return category.startswith("L") or category == "Nl"


# ---------------------------------------------------------------------------
# Decoding: zero-width binary, Tags-block ASCII, variation-selector payloads
# ---------------------------------------------------------------------------
_ZW_SCHEMES: tuple[tuple[str, dict[int, int]], ...] = (
    ("zwsp-zwnj", {0x200B: 0, 0x200C: 1}),
    ("zwsp-zwj", {0x200B: 0, 0x200D: 1}),
)


def _ascii_score(decoded: str) -> tuple[float, float]:
    """Return (printable_ratio, score) for a candidate plaintext decode."""
    if len(decoded) < 3:
        return 0.0, 0.0
    printable = sum(1 for ch in decoded if 0x20 <= ord(ch) <= 0x7E or ch in "\n\t")
    ratio = printable / len(decoded)
    alnum = sum(1 for ch in decoded if ch.isalnum())
    words = len(re.findall(r"[A-Za-z]{2,}", decoded))
    score = (
        ratio * 0.55
        + min(0.25, words * 0.06)
        + (0.10 if " " in decoded else 0.0)
        + min(0.10, alnum * 0.01)
    )
    return ratio, score


def _accept_ascii(decoded: str) -> tuple[bool, float, float]:
    """Decide whether a byte sequence is a credible ASCII payload."""
    ratio, score = _ascii_score(decoded)
    alnum = sum(1 for ch in decoded if ch.isalnum())
    words = len(re.findall(r"[A-Za-z]{2,}", decoded))
    if len(decoded) < 3 or ratio < 0.95 or words == 0:
        return False, ratio, score
    if len(decoded) < 8:
        # Short decodes need to be almost perfectly plain text to avoid noise.
        ok = ratio >= 0.999 and alnum * 5 >= len(decoded) * 3
        return ok, ratio, score
    ok = score >= 0.62 and alnum >= 2
    return ok, ratio, score


def _decode_zw_candidates(run: str, mapping: dict[int, int], scheme: str) -> list[Payload]:
    bits = [mapping[ord(ch)] for ch in run]
    candidates: list[Payload] = []
    for order in ("msb", "lsb"):
        for offset in range(8):
            chunk = bits[offset:]
            byte_count = len(chunk) // 8
            if byte_count < 3:
                continue
            values: list[int] = []
            for b in range(byte_count):
                part = chunk[b * 8 : b * 8 + 8]
                if order == "msb":
                    value = 0
                    for bit in part:
                        value = (value << 1) | bit
                else:
                    value = 0
                    for position, bit in enumerate(part):
                        value |= bit << position
                values.append(value)
            decoded = bytes(values).decode("ascii", errors="replace")
            ok, ratio, score = _accept_ascii(decoded)
            if ok:
                candidates.append(
                    Payload(
                        scheme="%s/%s" % (scheme, order),
                        start=0,
                        end=0,
                        decoded=decoded,
                        confidence=round(min(0.99, score), 3),
                        data={
                            "bits_offset": offset,
                            "bit_order": order,
                            "bits": len(chunk),
                            "bytes": byte_count,
                            "ascii_ratio": round(ratio, 3),
                            "mapping": {("U+%04X" % k): v for k, v in sorted(mapping.items())},
                        },
                    )
                )
    return candidates


def _decode_zero_width(text: str) -> list[Payload]:
    payloads: list[Payload] = []
    for scheme, mapping in _ZW_SCHEMES:
        allowed = set(mapping)
        i = 0
        n = len(text)
        while i < n:
            if ord(text[i]) in allowed:
                j = i
                while j < n and ord(text[j]) in allowed:
                    j += 1
                run = text[i:j]
                if len(run) >= 8:
                    candidates = _decode_zw_candidates(run, mapping, scheme)
                    if candidates:
                        best = max(candidates, key=lambda p: (p.confidence, -p.data["bits_offset"]))
                        payloads.append(
                            Payload(
                                scheme=best.scheme,
                                start=i,
                                end=j,
                                decoded=best.decoded,
                                confidence=best.confidence,
                                data=best.data,
                            )
                        )
                i = j
            else:
                i += 1
    return payloads


def _flag_base_before(text: str, start: int) -> bool:
    """True when the character(s) before ``start`` are a black-flag emoji base."""
    k = start - 1
    if k >= 0 and ord(text[k]) == 0xFE0F:  # optional emoji presentation selector
        k -= 1
    return k >= 0 and ord(text[k]) == 0x1F3F4


def _tag_flag_sequence(text: str, start: int, end: int) -> tuple[bool, str]:
    """Detect a legitimate emoji subdivision flag sequence such as 🏴󠁧󠁢󠁥󠁮󠁧󠁿."""
    if not _flag_base_before(text, start):
        return False, ""
    if ord(text[end - 1]) != TAG_CANCEL:
        return False, ""
    decoded = "".join(tag_to_ascii(ch) or "" for ch in text[start:end])
    if 2 <= len(decoded) <= 8 and decoded.isalpha() and decoded.islower():
        return True, decoded
    return False, ""


def _decode_tag(text: str) -> list[Payload]:
    payloads: list[Payload] = []
    i = 0
    n = len(text)
    while i < n:
        if is_tag(text[i]):
            j = i
            while j < n and is_tag(text[j]):
                j += 1
            benign, flag = _tag_flag_sequence(text, i, j)
            if not benign:
                decoded = "".join(tag_to_ascii(ch) or "" for ch in text[i:j])
                if len(decoded) >= 3:
                    ok, ratio, score = _accept_ascii(decoded)
                    if ok:
                        payloads.append(
                            Payload(
                                scheme="tag-ascii",
                                start=i,
                                end=j,
                                decoded=decoded,
                                confidence=round(min(0.99, 0.55 + score), 3),
                                data={
                                    "tag_chars": j - i,
                                    "ascii_ratio": round(ratio, 3),
                                    "has_cancel": ord(text[j - 1]) == TAG_CANCEL,
                                },
                            )
                        )
            i = j
        else:
            i += 1
    return payloads


def _decode_variation_selectors(text: str) -> list[Payload]:
    payloads: list[Payload] = []
    i = 0
    n = len(text)
    while i < n:
        if is_variation_selector(text[i]):
            start = i
            j = i
            while j < n and is_variation_selector(text[j]):
                j += 1
            run = text[start:j]
            i = j
            codes = [ord(ch) for ch in run]
            # Scheme A: VS1..VS16 (U+FE00..U+FE0F) are hex digits, two per byte.
            if len(codes) >= 4 and len(codes) % 2 == 0 and all(0xFE00 <= cp <= 0xFE0F for cp in codes):
                digits = [variation_selector_index(ch) for ch in run]
                values = [(digits[k] << 4) | digits[k + 1] for k in range(0, len(digits), 2)]
                decoded = bytes(values).decode("ascii", errors="replace")
                ok, ratio, score = _accept_ascii(decoded)
                if ok:
                    payloads.append(
                        Payload(
                            scheme="vs-hex-nibble",
                            start=start,
                            end=j,
                            decoded=decoded,
                            confidence=round(min(0.99, score), 3),
                            data={
                                "variation_selectors": len(run),
                                "ascii_ratio": round(ratio, 3),
                                "note": "VS1..VS16 map to hex digits 0..F, big-endian pairs",
                            },
                        )
                    )
            # Scheme B: U+E0100..U+E01EF carry one byte each (index 0..239).
            elif len(codes) >= 3 and all(0xE0100 <= cp <= 0xE01EF for cp in codes):
                values = [variation_selector_index(ch) for ch in run]
                decoded = bytes(values).decode("ascii", errors="replace")
                ok, ratio, score = _accept_ascii(decoded)
                if ok:
                    payloads.append(
                        Payload(
                            scheme="vs-byte",
                            start=start,
                            end=j,
                            decoded=decoded,
                            confidence=round(min(0.99, score), 3),
                            data={
                                "variation_selectors": len(run),
                                "ascii_ratio": round(ratio, 3),
                                "note": "U+E0100 + byte value, one selector per byte",
                            },
                        )
                    )
        else:
            i += 1
    return payloads


def decode(text: str) -> list[Payload]:
    """Decode hidden payloads carried by invisible characters.

    Supported schemes:
      * ``zwsp-zwnj/*`` and ``zwsp-zwj/*`` -- binary payloads where U+200B is
        a zero bit and U+200C (or U+200D) is a one bit; both MSB-first and
        LSB-first byte order and all 8 bit offsets are tried. ``*`` is the byte
        order (``msb``/``lsb``).
      * ``tag-ascii`` -- Tags block characters mapped back to ASCII
        (the "ASCII smuggling" scheme). Legitimate emoji subdivision flags are
        not reported.
      * ``vs-hex-nibble`` / ``vs-byte`` -- payloads encoded in variation
        selectors after an emoji or letter.

    Returns payloads sorted by start offset. Short accidental decodes are
    suppressed by a printable-ASCII + word-structure heuristic, and overlapping
    candidates are resolved deterministically by confidence then offset.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str, got %r" % (type(text).__name__,))
    candidates = (
        _decode_zero_width(text)
        + _decode_tag(text)
        + _decode_variation_selectors(text)
    )
    if not candidates:
        return []
    # Prefer higher confidence, then longer, then earlier.
    ordered = sorted(candidates, key=lambda p: (-p.confidence, -p.length, p.start, p.scheme))
    selected: list[Payload] = []
    occupied: list[tuple[int, int]] = []
    for candidate in ordered:
        if any(candidate.start < end and start < candidate.end for start, end in occupied):
            continue
        selected.append(candidate)
        occupied.append((candidate.start, candidate.end))
    selected.sort(key=lambda p: (p.start, p.end, p.scheme))
    return selected


# ---------------------------------------------------------------------------
# Scanning
# ---------------------------------------------------------------------------
def _bidi_finding(text: str, start: int, end: int, line_starts: list[int]) -> Finding:
    names = [BIDI_ALL[ord(ch)] for ch in text[start:end]]
    has_override = any(ord(ch) in BIDI_OVERRIDES for ch in text[start:end])
    has_terminator = any(ord(ch) in BIDI_TERMINATORS for ch in text[start:end])
    has_isolate = any(ord(ch) in BIDI_ISOLATES for ch in text[start:end])
    has_embedding = any(ord(ch) in BIDI_EMBEDDINGS for ch in text[start:end])
    if has_override:
        severity, code = "high", "IG-BIDI-OVERRIDE"
        message = (
            "Bidirectional override %s can visually reorder text (Trojan Source, "
            "CVE-2021-42574)" % ", ".join(names)
        )
    elif has_terminator:
        severity, code = "medium", "IG-BIDI-TERMINATOR"
        message = "Stray bidirectional terminator %s without a matching override/embedding" % ", ".join(names)
    elif has_isolate or has_embedding:
        if len(names) >= 2:
            severity = "high"
            message = (
                "Balanced bidirectional %s controls can hide reordered text "
                "(Trojan Source, CVE-2021-42574)"
                % ("isolate" if has_isolate else "embedding")
            )
        else:
            severity = "medium"
            message = "Single bidirectional %s control in plain text" % ("isolate" if has_isolate else "embedding")
        code = "IG-BIDI-ISOLATE" if has_isolate else "IG-BIDI-EMBEDDING"
    else:
        severity = "low" if len(names) == 1 else "medium"
        code = "IG-BIDI-MARK"
        message = "Directional mark %s (common in legitimate RTL text; suspicious only in Latin-heavy text)" % (
            ", ".join(names)
        )
    line, column = _line_col(line_starts, start)
    return Finding(
        code=code,
        kind="bidi_control",
        severity=severity,
        start=start,
        end=end,
        line=line,
        column=column,
        message=message,
        data={
            "controls": names,
            "codepoints": ["U+%04X" % ord(ch) for ch in text[start:end]],
        },
    )


def _tag_finding(text: str, start: int, end: int, line_starts: list[int]) -> Finding:
    benign, flag = _tag_flag_sequence(text, start, end)
    decoded = "".join(tag_to_ascii(ch) or "" for ch in text[start:end])
    line, column = _line_col(line_starts, start)
    codepoints = ["U+%05X" % ord(ch) for ch in text[start:end]]
    if benign:
        return Finding(
            code="IG-TAG-BENIGN-FLAG",
            kind="unicode_tag",
            severity="low",
            start=start,
            end=end,
            line=line,
            column=column,
            message=(
                "Tags-block sequence is part of a legitimate emoji subdivision flag "
                "sequence (decoded tag letters: %s)" % escape_visible(flag)
            ),
            data={
                "benign": True,
                "decoded": flag,
                "codepoints": codepoints,
                "note": "Emoji subdivision flags (e.g. England/Scotland/Wales) use the Tags block.",
            },
        )
    return Finding(
        code="IG-TAG-ASCII",
        kind="unicode_tag",
        severity="high",
        start=start,
        end=end,
        line=line,
        column=column,
        message=(
            "Unicode Tags-block characters encode invisible ASCII: %r"
            % (decoded[:120] + ("..." if len(decoded) > 120 else ""))
        ),
        data={
            "benign": False,
            "decoded": decoded,
            "tag_chars": end - start,
            "codepoints": codepoints,
            "note": "Tags block U+E0000..U+E007F mirrors ASCII and is invisible in most renderers.",
        },
    )


def _zw_finding(text: str, start: int, end: int, line_starts: list[int]) -> Finding:
    run = text[start:end]
    names: dict[str, int] = {}
    for ch in run:
        name = ZERO_WIDTH[ord(ch)]
        names[name] = names.get(name, 0) + 1
    severity = "high" if len(run) >= 8 else ("medium" if len(run) >= 2 else "low")
    line, column = _line_col(line_starts, start)
    if len(run) >= 8:
        message = (
            "Run of %d zero-width characters (%s) is long enough to encode a binary payload"
            % (len(run), ", ".join("%s x%d" % item for item in sorted(names.items())))
        )
    elif len(run) >= 2:
        message = "Multiple zero-width characters (%s) clustered in normal text" % ", ".join(
            "%s x%d" % item for item in sorted(names.items())
        )
    else:
        message = "Isolated zero-width character %s outside a recognised legitimate sequence" % (
            ", ".join("%s x%d" % item for item in sorted(names.items()))
        )
    return Finding(
        code="IG-ZW-RUN",
        kind="zero_width",
        severity=severity,
        start=start,
        end=end,
        line=line,
        column=column,
        message=message,
        data={
            "count": len(run),
            "chars": names,
            "codepoints": ["U+%04X" % ord(ch) for ch in run],
        },
    )


def _vs_finding(text: str, start: int, end: int, line_starts: list[int]) -> Finding | None:
    run = text[start:end]
    count = len(run)
    prev_char = text[start - 1] if start > 0 else ""
    if count == 1 and prev_char and _variation_selector_context_ok(text, start):
        return None  # presentation selector after a letter/emoji: normal
    if count >= 4:
        severity = "high"
        message = "Run of %d variation selectors can encode a hidden payload" % count
    elif count >= 2:
        severity = "medium"
        message = "Adjacent variation selectors (%d) are unusual and may encode data" % count
    else:
        severity = "low"
        message = "Variation selector without a plausible presentation base character"
    line, column = _line_col(line_starts, start)
    return Finding(
        code="IG-VS-RUN",
        kind="variation_selector",
        severity=severity,
        start=start,
        end=end,
        line=line,
        column=column,
        message=message,
        data={
            "count": count,
            "codepoints": ["U+%04X" % ord(ch) if ord(ch) <= 0xFFFF else "U+%05X" % ord(ch) for ch in run],
        },
    )


_SUSPICIOUS_SCRIPT_PAIRS = {
    frozenset(("LATIN", "CYRILLIC")): "high",
    frozenset(("LATIN", "GREEK")): "high",
    frozenset(("LATIN", "ARMENIAN")): "medium",
    frozenset(("LATIN", "HEBREW")): "medium",
    frozenset(("LATIN", "ARABIC")): "medium",
    frozenset(("LATIN", "CHEROKEE")): "medium",
    frozenset(("CYRILLIC", "GREEK")): "medium",
}

_CJK_FAMILY = {"CJK", "HIRAGANA", "KATAKANA", "HANGUL"}


def _confusable_findings(text: str, line_starts: list[int]) -> list[Finding]:
    findings: list[Finding] = []
    n = len(text)
    i = 0
    while i < n:
        if text[i].isalnum() or text[i] == "_":
            j = i
            while j < n and (text[j].isalnum() or text[j] == "_"):
                j += 1
            token = text[i:j]
            findings.extend(_check_token(token, i, line_starts))
            i = j
        else:
            i += 1
    return findings


def _check_token(token: str, start: int, line_starts: list[int]) -> list[Finding]:
    if len(token) < 2:
        return []
    scripts: dict[str, int] = {}
    homoglyphs: list[dict[str, Any]] = []
    for ch in token:
        script = script_of(ch)
        if script is None:
            continue
        if script in _CJK_FAMILY:
            script = "CJK"
        scripts[script] = scripts.get(script, 0) + 1
        if ord(ch) in HOMOGLYPHS:
            latin, name = HOMOGLYPHS[ord(ch)]
            homoglyphs.append(
                {
                    "char": ch,
                    "codepoint": "U+%04X" % ord(ch),
                    "name": name,
                    "looks_like": latin,
                }
            )
    if len(scripts) < 2:
        return []
    script_pair = frozenset(scripts)
    severity = "medium"
    matched = False
    for pair, pair_severity in _SUSPICIOUS_SCRIPT_PAIRS.items():
        if pair <= script_pair:
            severity = pair_severity
            matched = True
            break
    if not matched:
        return []  # e.g. Latin + CJK, or CJK-only mixes: not suspicious
    kind = "confusable"
    line, column = _line_col(line_starts, start)
    codepoints = ["U+%04X" % ord(ch) for ch in token]
    if homoglyphs:
        examples = "; ".join(
            "%s (%s) looks like Latin %r" % (item["char"], item["codepoint"], item["looks_like"])
            for item in homoglyphs[:3]
        )
        message = (
            "Token mixes scripts %s and contains homoglyph(s): %s"
            % ("+".join(sorted(scripts)), examples)
        )
    else:
        message = "Token mixes scripts %s inside one word" % "+".join(sorted(scripts))
    return [
        Finding(
            code="IG-CONF-MIXED-SCRIPT",
            kind=kind,
            severity=severity,
            start=start,
            end=start + len(token),
            line=line,
            column=column,
            message=message,
            data={
                "token": token,
                "scripts": scripts,
                "homoglyphs": homoglyphs,
                "codepoints": codepoints,
            },
        )
    ]


def _payload_finding(payload: Payload, line_starts: list[int]) -> Finding:
    if payload.scheme.startswith("zwsp"):
        code = "IG-ZW-ENC"
        kind = "encoded_payload"
        scheme_label = "zero-width binary"
    elif payload.scheme == "tag-ascii":
        code = "IG-TAG-ASCII"
        kind = "encoded_payload"
        scheme_label = "Tags-block ASCII"
    else:
        code = "IG-VS-ENC"
        kind = "encoded_payload"
        scheme_label = "variation selectors"
    line, column = _line_col(line_starts, payload.start)
    return Finding(
        code=code,
        kind=kind,
        severity="high",
        start=payload.start,
        end=payload.end,
        line=line,
        column=column,
        message="Hidden %s payload decodes to: %s" % (scheme_label, _preview(payload.decoded)),
        data={
            "scheme": payload.scheme,
            "decoded": payload.decoded,
            "confidence": payload.confidence,
            "payload_data": payload.data,
        },
    )


def _covered_by_payload(index: int, spans: list[tuple[int, int]]) -> bool:
    return any(start <= index < end for start, end in spans)


def scan(text: str) -> list[Finding]:
    """Scan ``text`` and return deterministic findings sorted by offset.

    The scanner is pure and stateless. Findings never include the invisible
    characters verbatim -- messages use escapes and codepoints so output is
    safe to paste into terminals, logs and CI results.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str, got %r" % (type(text).__name__,))
    findings: list[Finding] = []
    line_starts = _line_starts(text)
    payloads = decode(text)
    payload_spans = [(p.start, p.end) for p in payloads]
    found_payload_spans: set[tuple[int, int]] = set()

    # 1) Bidirectional controls, grouped when adjacent.
    i = 0
    n = len(text)
    while i < n:
        if is_bidi_control(text[i]):
            j = i
            while j < n and is_bidi_control(text[j]):
                j += 1
            findings.append(_bidi_finding(text, i, j, line_starts))
            i = j
        else:
            i += 1

    # 2) Tags block (including benign emoji subdivision flags).
    i = 0
    while i < n:
        if is_tag(text[i]):
            j = i
            while j < n and is_tag(text[j]):
                j += 1
            findings.append(_tag_finding(text, i, j, line_starts))
            i = j
        else:
            i += 1

    # 3) Zero-width runs outside legitimate sequence contexts.
    legit_zw: set[int] = set()
    if text.startswith("\ufeff"):
        legit_zw.add(0)
    for idx, ch in enumerate(text):
        if ch in ("\u200c", "\u200d") and _joiner_context_ok(text, idx):
            legit_zw.add(idx)
    i = 0
    while i < n:
        if (
            is_zero_width(text[i])
            and i not in legit_zw
            and not _covered_by_payload(i, payload_spans)
        ):
            j = i
            while (
                j < n
                and is_zero_width(text[j])
                and j not in legit_zw
                and not _covered_by_payload(j, payload_spans)
            ):
                j += 1
            findings.append(_zw_finding(text, i, j, line_starts))
            i = j
        else:
            i += 1

    # 4) Variation selectors (single legitimate presentation selectors skipped).
    i = 0
    while i < n:
        if is_variation_selector(text[i]) and not _covered_by_payload(i, payload_spans):
            j = i
            while j < n and is_variation_selector(text[j]) and not _covered_by_payload(j, payload_spans):
                j += 1
            finding = _vs_finding(text, i, j, line_starts)
            if finding is not None:
                findings.append(finding)
            i = j
        else:
            i += 1

    # 5) Mixed-script / homoglyph tokens.
    findings.extend(_confusable_findings(text, line_starts))

    # 5b) If an override or a balanced open/close bidi pair is present, the
    # whole bidi control group is a Trojan Source candidate at high severity.
    controls = [ord(ch) for ch in text if is_bidi_control(ch)]
    has_override = any(cp in BIDI_OVERRIDES for cp in controls)
    open_controls = {0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068}
    close_controls = {0x202C, 0x2069}
    balanced = bool(set(controls) & open_controls) and bool(set(controls) & close_controls)
    if has_override or balanced:
        upgraded: list[Finding] = []
        for finding in findings:
            if finding.code in (
                "IG-BIDI-OVERRIDE",
                "IG-BIDI-TERMINATOR",
                "IG-BIDI-EMBEDDING",
                "IG-BIDI-ISOLATE",
            ) and finding.severity != "high":
                upgraded.append(
                    Finding(
                        code=finding.code,
                        kind=finding.kind,
                        severity="high",
                        start=finding.start,
                        end=finding.end,
                        line=finding.line,
                        column=finding.column,
                        message=finding.message + " (paired with other bidi controls: Trojan Source pattern)",
                        data=dict(finding.data, paired=True),
                    )
                )
            else:
                upgraded.append(finding)
        findings = upgraded

    # 6) Decoded payload findings (Tags payloads are already surfaced above).
    for payload in payloads:
        if payload.scheme == "tag-ascii":
            continue
        span = (payload.start, payload.end)
        if span in found_payload_spans:
            continue
        found_payload_spans.add(span)
        findings.append(_payload_finding(payload, line_starts))

    unique: dict[tuple[str, int, int], Finding] = {}
    for finding in findings:
        unique.setdefault((finding.code, finding.start, finding.end), finding)
    return sorted(unique.values(), key=lambda f: (f.start, f.end, f.code))


# ---------------------------------------------------------------------------
# Sanitization
# ---------------------------------------------------------------------------
def _build_clean_plan(text: str) -> tuple[list[bool], dict[str, int], list[Payload]]:
    """Return (keep flags per code point, removed-character counts, payloads)."""
    n = len(text)
    keep = [True] * n
    payloads = decode(text)
    payload_spans = [(p.start, p.end) for p in payloads]
    counts = {
        "bidi_controls": 0,
        "zero_width": 0,
        "unicode_tag": 0,
        "variation_selector": 0,
    }
    for index in range(n):
        ch = text[index]
        in_payload = _covered_by_payload(index, payload_spans)
        if is_bidi_control(ch):
            keep[index] = False
            counts["bidi_controls"] += 1
        elif is_tag(ch):
            if not in_payload and _tag_flag_sequence_at(text, index):
                keep[index] = True
            else:
                keep[index] = False
                counts["unicode_tag"] += 1
        elif is_zero_width(ch):
            if _is_bom_position(text, index) and not in_payload:
                keep[index] = True
            elif ch in ("\u200c", "\u200d") and _joiner_context_ok(text, index) and not in_payload:  # noqa: E501
                keep[index] = True
            else:
                keep[index] = False
                counts["zero_width"] += 1
        elif is_variation_selector(ch):
            if in_payload:
                keep[index] = False
                counts["variation_selector"] += 1
            elif _single_vs_in_context(text, index):
                keep[index] = True
            else:
                keep[index] = False
                counts["variation_selector"] += 1
    counts["removed"] = sum(counts.values())
    return keep, counts, payloads


def _tag_flag_sequence_at(text: str, index: int) -> bool:
    """True when the tag character at ``index`` belongs to a benign flag sequence."""
    start = index
    while start > 0 and is_tag(text[start - 1]):
        start -= 1
    end = index
    while end < len(text) and is_tag(text[end]):
        end += 1
    benign, _flag = _tag_flag_sequence(text, start, end)
    return benign


def _single_vs_in_context(text: str, index: int) -> bool:
    if index > 0 and is_variation_selector(text[index - 1]):
        return False
    if index + 1 < len(text) and is_variation_selector(text[index + 1]):
        return False
    return _variation_selector_context_ok(text, index)


def clean(text: str, mode: str = "strip") -> str | dict[str, Any]:
    """Sanitize invisible characters from ``text``.

    Modes:
      ``strip``  -- remove attack characters, keep recognised legitimate ones
                    (UTF-8 BOM, ZWJ/ZWNJ in emoji/Indic/Arabic sequences,
                    single presentation variation selectors, subdivision-flag
                    tag sequences).
      ``escape`` -- same decisions but each removed code point is replaced by a
                    visible ``\\uXXXX`` / ``\\UXXXXXXXX`` marker.
      ``report`` -- do not modify anything; return a structured report with the
                    findings, decoded payloads, per-class removal counts and a
                    ``hidden_content`` boolean.

    Raises ``ValueError`` for unknown modes and ``TypeError`` for non-str input.
    """
    if not isinstance(text, str):
        raise TypeError("text must be str, got %r" % (type(text).__name__,))
    if mode not in ("strip", "escape", "report"):
        raise ValueError("mode must be 'strip', 'escape' or 'report', got %r" % (mode,))
    keep, counts, payloads = _build_clean_plan(text)
    findings = scan(text)
    if mode == "report":
        return {
            "tool": TOOL,
            "version": VERSION,
            "mode": "report",
            "input_chars": len(text),
            "removed_chars": counts["removed"],
            "removed_by_class": {key: value for key, value in counts.items() if key != "removed"},
            "findings": findings_to_dicts(findings),
            "payloads": [payload.to_dict() for payload in payloads],
            "summary": summarize(findings),
            "hidden_content": bool(payloads)
            or any(finding.severity in ("medium", "high") for finding in findings),
        }
    if mode == "strip":
        return "".join(ch for ch, keep_char in zip(text, keep) if keep_char)
    # escape
    parts: list[str] = []
    for ch, keep_char in zip(text, keep):
        if keep_char:
            parts.append(ch)
        else:
            cp = ord(ch)
            parts.append("\\u%04X" % cp if cp <= 0xFFFF else "\\U%08X" % cp)
    return "".join(parts)


# ---------------------------------------------------------------------------
# Helpers for reporting
# ---------------------------------------------------------------------------
def findings_to_dicts(findings: list[Finding]) -> list[dict[str, Any]]:
    return [finding.to_dict() for finding in findings]


def summarize(findings: list[Finding]) -> dict[str, Any]:
    """Count findings by severity and code (deterministic ordering)."""
    by_severity = {name: 0 for name in SEVERITIES}
    by_code: dict[str, int] = {}
    for finding in findings:
        by_severity[finding.severity] += 1
        by_code[finding.code] = by_code.get(finding.code, 0) + 1
    return {
        "total": len(findings),
        "low": by_severity["low"],
        "medium": by_severity["medium"],
        "high": by_severity["high"],
        "by_code": dict(sorted(by_code.items())),
    }


def max_severity(findings: list[Finding]) -> str | None:
    """Highest severity rank present, or ``None`` for an empty finding list."""
    if not findings:
        return None
    return max((finding.severity for finding in findings), key=lambda name: SEVERITY_RANK[name])
