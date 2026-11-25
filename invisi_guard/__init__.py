"""invisi_guard -- detect, decode and sanitize invisible-Unicode prompt injection.

Standard-library-only core. Example::

    from invisi_guard import scan, decode, clean

    findings = scan(document_text)      # list[Finding], deterministic order
    payloads = decode(document_text)    # list[Payload] with decoded hidden text
    safe = clean(document_text, "strip")      # str
    escaped = clean(document_text, "escape")  # str with visible \\uXXXX markers
    report = clean(document_text, "report")   # dict report, text unchanged

CLI::

    python -m invisi_guard scan memo.txt --fail-on high
    python -m invisi_guard decode memo.txt --json
    python -m invisi_guard clean memo.txt --mode escape
    python -m invisi_guard demo
"""

from __future__ import annotations

from .chars import TOOL, VERSION
from .codec import (
    encode_tag_ascii,
    encode_variation_selectors_bytes,
    encode_variation_selectors_hex,
    encode_zero_width_binary,
)
from .core import (
    SEVERITIES,
    SEVERITY_RANK,
    Finding,
    Payload,
    clean,
    decode,
    escape_visible,
    findings_to_dicts,
    max_severity,
    scan,
    summarize,
)

__version__ = VERSION
__all__ = [
    "Finding",
    "Payload",
    "SEVERITIES",
    "SEVERITY_RANK",
    "TOOL",
    "VERSION",
    "__version__",
    "clean",
    "decode",
    "escape_visible",
    "encode_tag_ascii",
    "encode_variation_selectors_bytes",
    "encode_variation_selectors_hex",
    "encode_zero_width_binary",
    "findings_to_dicts",
    "max_severity",
    "scan",
    "summarize",
]
