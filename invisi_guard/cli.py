"""Command line interface for invisi_guard.

Exit codes (stable, documented in README):

* 0 -- success / no findings at or above ``--fail-on`` threshold
* 1 -- findings at or above the ``--fail-on`` threshold (CI gating)
* 2 -- usage error, missing file, undecodable input, or internal failure

All output is deterministic: no timestamps, no locale dependence, no colors.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from . import demo as demo_module
from .chars import TOOL, VERSION
from .core import (
    SEVERITIES,
    SEVERITY_RANK,
    clean,
    decode,
    escape_visible,
    findings_to_dicts,
    max_severity,
    scan,
    summarize,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


class CliError(Exception):
    """Fatal CLI error that maps to exit code 2."""


def _reconfigure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            # newline="" keeps output byte-identical across platforms: the
            # sanitized text written by `clean` must not gain \r\n on Windows.
            stream.reconfigure(encoding="utf-8", errors="backslashreplace", newline="")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):  # pragma: no cover - platform dependent
            pass


def _read_input(path: str) -> tuple[str, str]:
    """Read text from a path or stdin (``-``); UTF-8 is required."""
    if path == "-":
        data = sys.stdin.buffer.read()
        name = "<stdin>"
    else:
        target = Path(path)
        try:
            data = target.read_bytes()
        except FileNotFoundError as exc:
            raise CliError("input file not found: %s" % path) from exc
        except OSError as exc:
            raise CliError("cannot read input file %s: %s" % (path, exc)) from exc
        name = str(target)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CliError(
            "input is not valid UTF-8 (byte offset %d): %s" % (exc.start, exc.reason)
        ) from exc
    return text, name


def _print_json(payload: Any) -> None:
    sys.stdout.write(json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=False) + "\n")


def _json_base(name: str) -> dict[str, Any]:
    return {"tool": TOOL, "version": VERSION, "file": name}


def _cmd_scan(args: argparse.Namespace) -> int:
    text, name = _read_input(args.input)
    findings = scan(text)
    summary = summarize(findings)
    highest = max_severity(findings)
    threshold_hit = False
    if args.fail_on:
        threshold_rank = SEVERITY_RANK[args.fail_on]
        threshold_hit = any(SEVERITY_RANK[finding.severity] >= threshold_rank for finding in findings)
    lines = text.count("\n") + 1 if text else 0
    if args.json:
        payload = _json_base(name)
        payload.update(
            {
                "operation": "scan",
                "chars": len(text),
                "lines": lines,
                "findings": findings_to_dicts(findings),
                "summary": summary,
                "max_severity": highest,
                "fail_on": args.fail_on,
                "threshold_hit": threshold_hit,
            }
        )
        _print_json(payload)
    else:
        sys.stdout.write(
            "%s %s  scan  %s  (%d chars, %d lines)\n" % (TOOL, VERSION, name, len(text), lines)
        )
        if not findings:
            sys.stdout.write("no findings.\n")
        else:
            for finding in findings:
                sys.stdout.write(
                    "%-6s %-24s line %d col %d (chars %d-%d)  %s\n"
                    % (
                        finding.severity.upper(),
                        finding.code,
                        finding.line,
                        finding.column,
                        finding.start,
                        finding.end,
                        finding.message,
                    )
                )
            sys.stdout.write(
                "summary: %d finding(s): %d high, %d medium, %d low\n"
                % (summary["total"], summary["high"], summary["medium"], summary["low"])
            )
        if args.fail_on:
            sys.stdout.write(
                "fail-on=%s: %s\n" % (args.fail_on, "THRESHOLD REACHED" if threshold_hit else "no findings at threshold")
            )
    return EXIT_FINDINGS if threshold_hit else EXIT_OK


def _cmd_decode(args: argparse.Namespace) -> int:
    text, name = _read_input(args.input)
    payloads = decode(text)
    if args.json:
        payload = _json_base(name)
        payload.update(
            {
                "operation": "decode",
                "chars": len(text),
                "payloads": [item.to_dict() for item in payloads],
                "summary": {"total": len(payloads)},
            }
        )
        _print_json(payload)
        return EXIT_OK
    sys.stdout.write("%s %s  decode  %s  (%d chars)\n" % (TOOL, VERSION, name, len(text)))
    if not payloads:
        sys.stdout.write("no hidden payloads decoded.\n")
        return EXIT_OK
    for index, item in enumerate(payloads, start=1):
        sys.stdout.write(
            "payload #%d  scheme=%s  chars=%d..%d (%d chars)  confidence=%.2f\n"
            % (index, item.scheme, item.start, item.end, item.length, item.confidence)
        )
        sys.stdout.write("  decoded: %s\n" % escape_visible(item.decoded))
    return EXIT_OK


def _cmd_clean(args: argparse.Namespace) -> int:
    text, name = _read_input(args.input)
    mode = args.mode
    if mode == "report":
        report = clean(text, "report")
        payload = {"file": name}
        payload.update(report)
        _print_json(payload)
        return EXIT_OK
    output = clean(text, mode)
    assert isinstance(output, str)
    if args.json:
        report = clean(text, "report")
        assert isinstance(report, dict)
        payload = _json_base(name)
        payload.update(
            {
                "operation": "clean",
                "mode": mode,
                "input_chars": len(text),
                "output_chars": len(output),
                "removed_chars": report["removed_chars"],
                "removed_by_class": report["removed_by_class"],
                "findings": report["findings"],
                "payloads": report["payloads"],
                "summary": report["summary"],
                "text": output,
            }
        )
        _print_json(payload)
        return EXIT_OK
    if args.output:
        target = Path(args.output)
        try:
            target.write_bytes(output.encode("utf-8"))
        except OSError as exc:
            raise CliError("cannot write output file %s: %s" % (args.output, exc)) from exc
        sys.stdout.write("wrote %d chars to %s\n" % (len(output), args.output))
        return EXIT_OK
    sys.stdout.write(output)
    return EXIT_OK


def _cmd_demo(args: argparse.Namespace) -> int:
    demo = demo_module.build_demo()
    html_path: Path | None = None
    if args.html:
        html_path = demo_module.write_demo_html(args.html, demo)
    if args.json:
        payload = {
            "tool": TOOL,
            "version": VERSION,
            "operation": "demo",
            "clean_chars": demo["clean_chars"],
            "poisoned_chars": demo["poisoned_chars"],
            "hidden_chars": demo["hidden_chars"],
            "stripped_equals_clean": demo["stripped_equals_clean"],
            "findings": demo["findings"],
            "summary": demo["summary"],
            "max_severity": demo["max_severity"],
            "payloads": demo["payloads"],
            "html": str(html_path) if html_path else None,
        }
        _print_json(payload)
        return EXIT_OK
    sys.stdout.write("%s %s  demo -- deterministic hidden-instruction demo\n\n" % (TOOL, VERSION))
    sys.stdout.write(
        "clean memo    : %d chars\npoisoned memo : %d chars (+%d invisible characters)\n\n"
        % (demo["clean_chars"], demo["poisoned_chars"], demo["hidden_chars"])
    )
    sys.stdout.write("visible text after strip() == clean memo: %s\n\n" % demo["stripped_equals_clean"])
    sys.stdout.write("hidden instructions decoded from the poisoned memo:\n")
    for payload in demo["payloads"]:
        sys.stdout.write(
            "  - %s: %s\n" % (payload["scheme"], escape_visible(payload["decoded"]))
        )
    sys.stdout.write("\nfindings:\n")
    for finding in demo["findings"]:
        sys.stdout.write(
            "  [%s] %s (line %d col %d) %s\n"
            % (
                finding["severity"].upper(),
                finding["code"],
                finding["line"],
                finding["column"],
                finding["message"],
            )
        )
    sys.stdout.write(
        "\nsummary: %d finding(s): %d high, %d medium, %d low\n"
        % (demo["summary"]["total"], demo["summary"]["high"], demo["summary"]["medium"], demo["summary"]["low"])
    )
    if html_path:
        sys.stdout.write("\ndemo page written to: %s\n" % html_path)
    return EXIT_OK


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="invisi_guard",
        description=(
            "Detect, decode and sanitize invisible-Unicode prompt injection "
            "(zero-width characters, bidi controls, Unicode Tags ASCII smuggling, "
            "variation selectors, homoglyph token mixing)."
        ),
    )
    parser.add_argument("--version", action="version", version="%(prog)s " + VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan text for invisible Unicode abuse")
    scan_parser.add_argument("input", help="UTF-8 file path, or '-' for stdin")
    scan_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    scan_parser.add_argument(
        "--fail-on",
        choices=SEVERITIES,
        default=None,
        help="exit with code 1 when a finding at or above this severity exists (CI gating)",
    )
    scan_parser.set_defaults(func=_cmd_scan)

    clean_parser = subparsers.add_parser("clean", help="sanitize invisible characters")
    clean_parser.add_argument("input", help="UTF-8 file path, or '-' for stdin")
    clean_parser.add_argument(
        "--mode",
        choices=("strip", "escape", "report"),
        default="strip",
        help="strip = remove attack chars; escape = visible \\uXXXX markers; report = JSON report only",
    )
    clean_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    clean_parser.add_argument("-o", "--output", default=None, help="write cleaned text to this file")
    clean_parser.set_defaults(func=_cmd_clean)

    decode_parser = subparsers.add_parser("decode", help="decode hidden payloads")
    decode_parser.add_argument("input", help="UTF-8 file path, or '-' for stdin")
    decode_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    decode_parser.set_defaults(func=_cmd_decode)

    demo_parser = subparsers.add_parser("demo", help="run the deterministic built-in demo")
    demo_parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    demo_parser.add_argument(
        "--html",
        default=None,
        metavar="PATH",
        help="also write the self-contained HTML demo page to PATH",
    )
    demo_parser.set_defaults(func=_cmd_demo)
    return parser


def main(argv: list[str] | None = None) -> int:
    _reconfigure_stdio()
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except CliError as exc:
        sys.stderr.write("%s: error: %s\n" % (TOOL, exc))
        return EXIT_ERROR
    except BrokenPipeError:  # pragma: no cover - pipe closure
        return EXIT_ERROR
    except (ValueError, TypeError) as exc:  # defensive: invalid API-level input
        sys.stderr.write("%s: error: %s\n" % (TOOL, exc))
        return EXIT_ERROR


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
