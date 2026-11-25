# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-11-25

Initial public release. This is a detection/sanitization tool plus a local
demonstration; it does not describe a newly discovered vulnerability and does not
claim any CVE.

### Added

- `invisi_guard` core package (standard library only, Python 3.10+):
  - `scan(text)` — deterministic findings for bidirectional controls, zero-width
    characters, Unicode Tags block, variation selectors, mixed-script tokens and
    homoglyphs, plus decoded hidden-payload findings.
  - `decode(text)` — decodes zero-width binary (`U+200B`/`U+200C` or `U+200D`,
    MSB/LSB, all 8 bit offsets), Tags-block ASCII (`tag-ascii`), and
    variation-selector payloads (`vs-hex-nibble`, `vs-byte`).
  - `clean(text, mode)` — `strip`, `escape` (`\uXXXX` markers) and `report` modes
    with an explicit allow-list for legitimate BOM/emoji/Indic/Arabic/flag uses.
- CLI `python -m invisi_guard` with `scan`, `decode`, `clean`, `demo` commands,
  `--json` output, `--fail-on {low,medium,high}` CI gating and stable exit codes
  (0/1/2). Byte-exact stdout for `clean`.
- Codepoint/encoding helpers (`invisi_guard.codec`) with reference encoders used
  by tests and demos.
- 136 unit tests (unittest; also collected by pytest), including fixtures with
  real invisible characters and a dedicated false-positive suite for Arabic,
  Hebrew, Persian, emoji, Indic and CJK text.
- GitHub Actions CI (Python 3.10/3.11/3.12): stdlib-only core check, unittest,
  pytest, CLI smoke tests, deterministic demo regeneration and both expected
  outcomes of the `--fail-on` gate.
- JSON Schemas for findings and scan results (`docs/finding.schema.json`,
  `docs/scan-result.schema.json`) plus a dependency-free schema validator in the
  test suite.
- Reproducible demo: `docs/demo.html` and `docs/demo_revealed.html` are generated
  from the tool itself; the page contains real invisible payloads and independent
  JavaScript decoding that is compared with Python output (verified with headless
  Edge).
- Evidence pipeline: `scripts/capture_evidence.py` writes `docs/EVIDENCE.md` with
  real hex dumps, SHA-256 hashes, CLI outputs, test summary and the local model
  run; `scripts/clipboard_check.ps1` verifies OS clipboard round-trip preservation.
- Documentation: `docs/THREAT_MODEL.md` (attack classes, severity rationale,
  benign exceptions, citations), README (English + Chinese), CONTRIBUTING.
- Screenshots in `docs/screenshots/`: demo page (normal/revealed), terminal
  session, GitHub repository page.

### Demonstrated (honest results)

- Clean vs. poisoned memo: visible text identical, 432 invisible characters
  added, `clean(strip)` restores the exact clean memo; both hidden payloads are
  decoded.
- Windows clipboard: payload bytes survive a `Set-Clipboard`/`Get-Clipboard` round
  trip byte-for-byte (matching UTF-8 SHA-256).
- Local model (Qwen2.5-0.5B-Instruct, greedy decoding): the model answered the
  benign question from the visible document in all hidden-payload variants (it did
  **not** follow the hidden instruction) while it did obey the identical
  instruction when it was visible. Hidden characters survive tokenization into the
  model context exactly. This negative result is recorded as measured.

### Notes

- No new CVE, no responsible-disclosure claim. Prior art: Trojan Source
  (CVE-2021-42574/CVE-2021-42694), ASCII smuggling reporting (2024),
  indirect prompt injection research, variation-selector jailbreak research.
- Detection is heuristic; see the limitations in `docs/THREAT_MODEL.md`.
