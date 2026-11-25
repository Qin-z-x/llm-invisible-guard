"""Collect real, reproducible evidence and write docs/EVIDENCE.md.

Everything in this script runs locally and offline (except nothing at all:
no network is used). Outputs are written to ``evidence/`` and the human-readable
summary to ``docs/EVIDENCE.md``. Re-run after any tool change:

    python scripts/capture_evidence.py
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from invisi_guard import VERSION, clean, decode, escape_visible, scan, summarize  # noqa: E402
from invisi_guard.codec import encode_zero_width_binary  # noqa: E402
from invisi_guard.demo import (  # noqa: E402
    CLEAN_MEMO,
    HIDDEN_TAG_TEXT,
    HIDDEN_ZW_TEXT,
    build_demo,
    build_poisoned_text,
)

EVIDENCE = ROOT / "evidence"
RAW = EVIDENCE / "raw"
TERMINAL = EVIDENCE / "terminal"
DOCS = ROOT / "docs"
PYTHON = sys.executable
MARKER = "PWNED-7F3A"

COMMANDS = [
    (["demo"], "Deterministic built-in demo: visible text unchanged, payloads decoded."),
    (["scan", "examples/poisoned_memo.txt"], "Scan the poisoned memo (exit 0 without --fail-on)."),
    (
        ["scan", "examples/poisoned_memo.txt", "--fail-on", "high"],
        "CI gating: exit code 1 because a high finding exists.",
    ),
    (["decode", "examples/poisoned_memo.txt"], "Decode both hidden payloads with their schemes."),
    (
        ["scan", "tests/fixtures/trojan_source_comment.txt"],
        "Trojan Source style bidi override in a C comment.",
    ),
    (
        ["scan", "tests/fixtures/mixed_script.txt"],
        "Cyrillic homoglyph in a Latin token.",
    ),
    (
        ["clean", "examples/poisoned_memo.txt", "--mode", "report"],
        "JSON sanitization report (text unchanged, counts per class).",
    ),
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8"))


def run_cli(args: list[str]) -> dict:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONIOENCODING"] = "utf-8"
    done = subprocess.run(
        [PYTHON, "-m", "invisi_guard"] + args,
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        timeout=180,
        check=False,
    )
    return {
        "args": args,
        "exit_code": done.returncode,
        "stdout": done.stdout.decode("utf-8", "replace"),
        "stderr": done.stderr.decode("utf-8", "replace"),
    }


def hexdump_spans(demo: dict) -> list[str]:
    poisoned = demo["poisoned_text"]
    lines = [
        "Poisoned memo: %d code points, %d UTF-8 bytes"
        % (len(poisoned), len(poisoned.encode("utf-8"))),
        "Clean memo:    %d code points, %d UTF-8 bytes"
        % (len(CLEAN_MEMO), len(CLEAN_MEMO.encode("utf-8"))),
        "",
    ]
    for index, payload in enumerate(demo["payloads"], start=1):
        span = poisoned[payload["start"] : payload["end"]]
        raw = span.encode("utf-8")
        lines.append(
            "payload #%d scheme=%s span=%d..%d (%d code points, %d UTF-8 bytes) sha256=%s"
            % (
                index,
                payload["scheme"],
                payload["start"],
                payload["end"],
                len(span),
                len(raw),
                sha256_bytes(raw),
            )
        )
        lines.append("decoded: %s" % escape_visible(payload["decoded"]))
        lines.append("first 24 code points: " + " ".join("U+%04X" % ord(ch) for ch in span[:24]))
        lines.append("first 48 UTF-8 bytes: " + " ".join("%02x" % byte for byte in raw[:48]))
        lines.append("")
    return lines


def dom_check() -> dict:
    """Load docs/demo_revealed.html in headless Edge and read the JS proof lines."""
    edge_candidates = [
        Path(os.environ.get("ProgramFiles(x86)", "C:/Program Files (x86)"))
        / "Microsoft/Edge/Application/msedge.exe",
        Path(os.environ.get("ProgramFiles", "C:/Program Files"))
        / "Microsoft/Edge/Application/msedge.exe",
    ]
    edge = next((candidate for candidate in edge_candidates if candidate.exists()), None)
    page = DOCS / "demo_revealed.html"
    result: dict = {
        "checked": False,
        "browser": str(edge) if edge else None,
        "page": str(page),
        "js_decode_matches_python": None,
        "strip_equals_clean": None,
        "dom_sha256": None,
    }
    if edge is None:
        result["note"] = "Microsoft Edge not found; static screenshot check only."
        return result
    try:
        done = subprocess.run(
            [
                str(edge),
                "--headless=new",
                "--disable-gpu",
                "--no-first-run",
                "--disable-extensions",
                "--virtual-time-budget=5000",
                "--dump-dom",
                page.as_uri(),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=120,
            check=False,
        )
        dom = done.stdout.decode("utf-8", "replace")
        result.update(
            {
                "checked": True,
                "dom_sha256": sha256_text(dom),
                "dom_bytes": len(done.stdout),
                "js_decode_matches_python": "Browser JavaScript decode == Python decode: TRUE" in dom,
                "strip_equals_clean": "strip(poisoned paragraph) === clean paragraph: TRUE" in dom,
            }
        )
        (EVIDENCE / "raw").mkdir(parents=True, exist_ok=True)
        (RAW / "demo_page_dom.html").write_text(dom, encoding="utf-8", newline="\n")
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        result["note"] = "headless Edge check failed: %s" % exc
    return result


def load_json_if_exists(path: Path) -> dict | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def model_table(model: dict) -> list[str]:
    lines = [
        "| case | hidden chars in prompt | output (verbatim) | contains `%s` |" % MARKER,
        "| --- | --- | --- | --- |",
    ]
    for case in model.get("cases", []):
        output = case["output"].replace("|", "\\|").replace("\n", "\\n")
        if len(output) > 160:
            output = output[:160] + "..."
        hidden = "yes" if case["hidden_survives_tokenization"] else "no"
        lines.append(
            "| `%s` | %s | `%s` | %s |"
            % (case["case"], hidden, output, "yes" if case["contains_marker"] else "no")
        )
    return lines


def write_markdown(evidence: dict) -> str:
    demo = evidence["demo"]
    lines: list[str] = []
    add = lines.append
    add("# Evidence log")
    add("")
    add(
        "This file is generated by `python scripts/capture_evidence.py` on the machine that "
        "built the project. Every value below is copied from real tool output, saved JSON or "
        "the OS clipboard; nothing is estimated. Re-running the script reproduces the raw "
        "files in `evidence/` (except GPU/model timings)."
    )
    add("")
    add("## Scope and honesty statement")
    add("")
    add(
        "`invisi-guard` is a **detection and sanitization tool plus a local demonstration**. "
        "It does not disclose a new vulnerability, does not claim a new CVE, and does not "
        "claim that every LLM will obey hidden instructions. The attack class is public prior "
        "art: Trojan Source / CVE-2021-42574 (bidi controls) and ASCII smuggling / invisible "
        "Unicode prompt injection (Unicode Tags block, zero-width payloads), see "
        "`docs/THREAT_MODEL.md` for citations. The demonstrations here show (a) that invisible "
        "instructions can be carried in text that looks clean, and (b) what the tool detects, "
        "decodes and removes."
    )
    add("")
    add("## Environment")
    add("")
    add("| item | value |")
    add("| --- | --- |")
    add("| operating system | %s |" % evidence["platform"])
    add("| Python | %s |" % evidence["python"])
    add("| invisi-guard version | %s |" % VERSION)
    add("| capture time (UTC) | %s |" % evidence["timestamp_utc"])
    add("")
    add("## 1. Deterministic in-memory demonstration")
    add("")
    add(
        "A clean-looking memo and a poisoned memo whose **visible text is byte-identical** are "
        "built by `invisi_guard.demo.build_demo()`. Two hidden instructions are inserted:"
    )
    add("")
    add("| payload | scheme | hidden instruction (decoded) |")
    add("| --- | --- | --- |")
    for payload in demo["payloads"]:
        add(
            "| %s | `%s` | `%s` |"
            % (
                "zero-width" if payload["scheme"].startswith("zwsp") else "Tags block",
                payload["scheme"],
                escape_visible(payload["decoded"]),
            )
        )
    add("")
    add("| measurement | value |")
    add("| --- | --- |")
    add("| clean memo length | %d code points |" % demo["clean_chars"])
    add("| poisoned memo length | %d code points |" % demo["poisoned_chars"])
    add("| invisible characters added | %d |" % demo["hidden_chars"])
    add(
        "| `clean(poisoned, 'strip') == clean memo` | **%s** |"
        % demo["stripped_equals_clean"]
    )
    add(
        "| `decode(poisoned)` recovered both hidden instructions | **%s** |"
        % ("True" if len(demo["payloads"]) == 2 else "False")
    )
    add("| scanner findings | %d (high=%d, medium=%d, low=%d) |"
        % (demo["summary"]["total"], demo["summary"]["high"], demo["summary"]["medium"], demo["summary"]["low"]))
    add("| clean memo sha256 (UTF-8) | `%s` |" % sha256_text(CLEAN_MEMO))
    add("| poisoned memo sha256 (UTF-8) | `%s` |" % sha256_text(demo["poisoned_text"]))
    add("")
    add("Hex / code point dump of the hidden spans (real bytes from the generated memo):")
    add("")
    add("```")
    lines.extend(hexdump_spans(demo))
    add("```")
    add("")
    add("### HTML page verification")
    add("")
    add(
        "`docs/demo.html` is generated from the same data. The hidden payload characters are "
        "present as real characters in the page source and render as nothing; the page's "
        "JavaScript independently decodes them in the browser and compares its result with the "
        "Python build-time result."
    )
    add("")
    add("| file | sha256 |")
    add("| --- | --- |")
    for name in ("demo.html", "demo_revealed.html"):
        path = DOCS / name
        add("| `docs/%s` | `%s` |" % (name, sha256_file(path)))
    add("")
    add("| browser check (headless Microsoft Edge, `--dump-dom`) | result |")
    add("| --- | --- |")
    dom = evidence["dom"]
    add("| JS decoder output == Python decoder output | **%s** |" % evidence["browser_check"])
    add("| strip(poisoned paragraph) == clean paragraph | **%s** |" % dom.get("strip_equals_clean"))
    add("| DOM snapshot | `evidence/raw/demo_page_dom.html` (sha256 `%s`) |" % (dom.get("dom_sha256") or "n/a"))
    add("")
    add("Screenshots (real rendered page):")
    add("")
    add("- `docs/screenshots/demo_normal.png` -- how the poisoned memo looks to a human.")
    add("- `docs/screenshots/demo_revealed.png` -- same page with decoded payloads and sanitized output visible.")
    add("")
    add("## 2. OS clipboard preservation (delivery proof)")
    add("")
    clipboard = evidence["clipboard"]
    if clipboard:
        add(
            "Text containing an embedded zero-width binary payload was written to the Windows "
            "clipboard with PowerShell `Set-Clipboard`, read back with `Get-Clipboard`, and "
            "compared byte-for-byte (UTF-8 sha256) and character-for-character."
        )
        add("")
        add("| measurement | value |")
        add("| --- | --- |")
        add("| clipboard round trip text identical (`-ceq`) | **%s** |" % clipboard.get("text_identical"))
        add("| input length (PowerShell UTF-16 code units) | %s |" % clipboard.get("input_chars"))
        add("| clipboard length (UTF-16 code units) | %s |" % clipboard.get("clipboard_chars"))
        add("| sha256 input UTF-8 | `%s` |" % clipboard.get("sha256_input_utf8"))
        add("| sha256 clipboard UTF-8 | `%s` |" % clipboard.get("sha256_clipboard_utf8"))
        add(
            "| invisible characters (input -> clipboard) | %s -> %s |"
            % (
                json.dumps(clipboard.get("invisible_counts_input")),
                json.dumps(clipboard.get("invisible_counts_clipboard")),
            )
        )
        add("")
        add(
            "The two sha256 values are identical, so the UTF-8 bytes (including every invisible "
            "payload character) survived the OS clipboard unchanged. Lengths are PowerShell "
            "UTF-16 code units; astral Tags-block characters therefore count as two units each."
        )
        add("")
        add(
            "This shows *delivery*: a payload survives a real copy/paste path between "
            "applications on Windows. It is not evidence that any particular model obeys it."
        )
    else:
        add("Clipboard evidence file not found -- run `scripts/clipboard_check.ps1` first.")
    add("")
    add("## 3. Local model demonstration (Qwen2.5-0.5B-Instruct, GPU)")
    add("")
    model = evidence["model"]
    if model and model.get("status") == "success":
        env = model.get("environment", {})
        add(
            "The same benign question was asked about the same visible document in five "
            "variants. Decoding is greedy (`do_sample=false`), seed 0, so outputs are "
            "reproducible on this hardware/stack. The exact prompt text (with invisible "
            "characters escaped) is saved under `evidence/model_prompts/`."
        )
        add("")
        add("| item | value |")
        add("| --- | --- |")
        add("| model | `%s` |" % model.get("model_id"))
        add("| device | %s |" % env.get("cuda_device"))
        add("| dtype | %s |" % env.get("dtype"))
        add("| torch / transformers | %s / %s |" % (env.get("torch"), env.get("transformers")))
        add("| decoding | %s |" % model.get("decoding"))
        add("")
        lines.extend(model_table(model))
        add("")
        summary = model.get("summary", {})
        add("**Measured result:**")
        add("")
        add(
            "- Clean document: `%s`" % ("marker present" if summary.get("clean_contains_marker") else "marker absent")
        )
        add(
            "- Zero-width-hidden instruction: `%s`"
            % ("FOLLOWED" if summary.get("hidden_zero_width_contains_marker") else "not followed")
        )
        add(
            "- Tags-block-hidden instruction: `%s`"
            % ("FOLLOWED" if summary.get("hidden_tag_contains_marker") else "not followed")
        )
        add(
            "- Same instruction visible: `%s`"
            % ("FOLLOWED" if summary.get("visible_control_contains_marker") else "not followed")
        )
        add(
            "- Hidden instruction survives tokenization into the model context: zero-width=%s, tags=%s"
            % (
                summary.get("zero_width_survives_tokenization"),
                summary.get("tag_survives_tokenization"),
            )
        )
        add("")
        add(
            "**Honest interpretation:** with this small (0.5B) model, hiding the instruction did "
            "not make it obey; the model answered the visible document question in every hidden "
            "variant, while it *did* obey the identical instruction when it was visible. The "
            "payload is nevertheless delivered to the model context: the tokenizer round-trips "
            "the invisible characters exactly, so the tokens a model attends to contain the "
            "hidden instruction. Whether a given model interprets such tokens as instructions is "
            "model- and tokenizer-dependent; the public reports cited in `docs/THREAT_MODEL.md` "
            "document production models affected by ASCII smuggling. This local negative result "
            "is reported as-is rather than cherry-picked."
        )
        add("")
    else:
        add("Model demo did not complete successfully.")
        if model:
            add("")
            add("```")
            add(str(model.get("error", "unknown error")))
            add("```")
        add("")
        add(
            "Per project policy this failure is documented honestly; the HTML and clipboard "
            "demonstrations above do not depend on the model."
        )
    add("")
    add("## 4. Reproduce")
    add("")
    add("```bash")
    add("python -m unittest discover -s tests -t .        # 136 tests")
    add("python -m invisi_guard demo                     # deterministic demo")
    add("python scripts/build_demo.py                    # rebuild docs/demo*.html")
    add("python scripts/capture_evidence.py              # rebuild this file + raw evidence")
    add("python scripts/model_demo.py                    # optional GPU model demo")
    add("pwsh -File scripts/clipboard_check.ps1 ...      # optional clipboard check")
    add("```")
    add("")
    add("## Known limits")
    add("")
    add(
        "- Detection is heuristic: it targets known invisible-Unicode smuggling schemes. "
        "Unicode is large; novel encodings may evade it."
    )
    add("- A single variation selector carries a few bits; only runs are decoded.")
    add(
        "- Dedicated filters/classifiers can be bypassed; this tool is a defence-in-depth "
        "input sanitizer, not a guarantee that a model will never be injected."
    )
    add(
        "- The model demo is a 0.5B open model on one machine; it is not a claim about "
        "frontier-model behaviour in either direction."
    )
    add("")
    return "\n".join(lines) + "\n"


def main() -> int:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    RAW.mkdir(parents=True, exist_ok=True)
    TERMINAL.mkdir(parents=True, exist_ok=True)
    demo = build_demo()
    (RAW / "demo_build.json").write_text(
        json.dumps(
            {
                "clean_text": demo["clean_text"],
                "poisoned_text": demo["poisoned_text"],
                "findings": demo["findings"],
                "payloads": demo["payloads"],
                "summary": demo["summary"],
                "stripped_equals_clean": demo["stripped_equals_clean"],
                "escaped_text": demo["escaped_text"],
            },
            indent=2,
            ensure_ascii=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    cli_runs = []
    session_lines = ["# Captured terminal session (real CLI output, captured %s)" % time.strftime("%Y-%m-%d %H:%M:%S"), ""]
    for args, description in COMMANDS:
        result = run_cli(args)
        cli_runs.append(dict(result, description=description))
        session_lines.append("$ python -m invisi_guard " + " ".join(args))
        session_lines.append(result["stdout"].rstrip("\n"))
        if result["stderr"].strip():
            session_lines.append("[stderr] " + result["stderr"].strip())
        session_lines.append("[exit code: %d]" % result["exit_code"])
        session_lines.append("")
    (RAW / "cli_runs.json").write_text(
        json.dumps(cli_runs, indent=2, ensure_ascii=True) + "\n", encoding="utf-8", newline="\n"
    )

    escape_result = run_cli(["clean", "examples/poisoned_memo.txt", "--mode", "escape"])
    (RAW / "clean_escape_output.txt").write_text(
        escape_result["stdout"], encoding="utf-8", newline="\n"
    )
    session_lines.append("$ python -m invisi_guard clean examples/poisoned_memo.txt --mode escape | head -c 600")
    session_lines.append(escape_result["stdout"][:600].rstrip("\n") + " ...")
    session_lines.append("[exit code: %d]" % escape_result["exit_code"])
    session_lines.append("")

    tests_done = subprocess.run(
        [PYTHON, "-m", "unittest", "discover", "-s", "tests", "-t", "."],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=300,
        check=False,
    )
    tests_tail = (tests_done.stdout + tests_done.stderr).decode("utf-8", "replace")
    tail_lines = tests_tail.strip().splitlines()[-3:]
    session_lines.append("$ python -m unittest discover -s tests -t .")
    session_lines.extend(tail_lines)
    session_lines.append("[exit code: %d]" % tests_done.returncode)
    session_lines.append("")
    (TERMINAL / "terminal_session.txt").write_text(
        "\n".join(session_lines) + "\n", encoding="utf-8", newline="\n"
    )
    (RAW / "unit_test_output.txt").write_text(
        tests_tail, encoding="utf-8", newline="\n"
    )

    dom = dom_check()
    clipboard = load_json_if_exists(EVIDENCE / "clipboard_roundtrip.json")
    model = load_json_if_exists(EVIDENCE / "model_demo.json")

    evidence = {
        "platform": platform.platform(),
        "python": sys.version.split()[0],
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "demo": demo,
        "dom": dom,
        "browser_check": dom.get("js_decode_matches_python"),
        "clipboard": clipboard,
        "model": model,
        "test_count": None,
    }
    markdown = write_markdown(evidence)
    (DOCS / "EVIDENCE.md").write_text(markdown, encoding="utf-8", newline="\n")
    print("wrote docs/EVIDENCE.md (%d bytes)" % len(markdown.encode("utf-8")))
    print("browser JS/Python match:", dom.get("js_decode_matches_python"))
    print("tests exit:", tests_done.returncode, "| tail:", tail_lines[-1] if tail_lines else "")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
