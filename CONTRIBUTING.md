# Contributing to invisi-guard

Thanks for helping make invisible-Unicode injection easier to defend against.
This project values **honesty and reproducibility over impressive claims**.

## Ground rules

1. **No fabricated evidence.** If you report a demo result, include the exact
   command and raw output. Negative results are welcome and must not be hidden.
2. **The core stays standard-library only.** `invisi_guard/` must not import
   third-party packages. CI enforces this with `scripts/check_core_deps.py`.
3. **Deterministic output.** Findings are sorted and contain no timestamps,
   randomness, or locale-dependent formatting. Do not add network access to the
   core.
4. **No weaponized payloads.** Test fixtures use harmless markers such as
   `PWNED-7F3A` and never contain real malware, secrets or working exploit
   chains.
5. **No premature disclosure.** This project does not publish new vulnerabilities
   without coordinated disclosure to the affected vendor; do not open issues
   containing live exploit material.

## Development setup

```bash
git clone https://github.com/Qin-Z-x/llm-invisible-guard.git
cd llm-invisible-guard
python --version                      # 3.10+
python -m unittest discover -s tests -t .   # no install needed
# optional: pip install -e .[dev]
```

## Running tests

```bash
python scripts/check_core_deps.py
python -m unittest discover -s tests -t .
python -m pytest                       # if pytest is installed
```

If you change detection or cleaning behaviour, add tests to the relevant file:

* `tests/test_scan.py` — detection rules and finding contract;
* `tests/test_decode.py` — decoding schemes and false-positive decoding;
* `tests/test_clean.py` — strip/escape/report behaviour;
* `tests/test_cli.py` — exit codes, JSON output, stdin/stdout;
* `tests/test_false_positives.py` — legitimate text that must not be flagged;
* `tests/test_schema.py` — JSON Schema conformance.

## Adding a new detection rule

1. Add the character classes to `invisi_guard/chars.py` with a doc reference.
2. Implement the rule in `invisi_guard/core.py`, emit a `Finding` with a stable
   `IG-…` code, a documented severity and structured `data`.
3. Decide explicitly whether `clean()` should strip or preserve the sequence and
   document it (benign exceptions go in `_build_clean_plan`).
4. Add positive tests, negative tests, and a fixture if the characters are hard to
   type. Regenerate fixtures with `python scripts/gen_fixtures.py`.
5. Update `docs/THREAT_MODEL.md` (severity table), `README.md` (rule table) and
   `CHANGELOG.md`.
6. Run `python scripts/capture_evidence.py` if the change affects the demo and
   include the diff in the PR description.

## Regenerating artifacts

```bash
python scripts/gen_fixtures.py      # tests/fixtures/* and examples/*
python scripts/build_demo.py        # docs/demo.html, docs/demo_revealed.html
python scripts/capture_evidence.py  # docs/EVIDENCE.md + evidence/raw/*
```

Commit regenerated files together with the source change. CI verifies that the
demo pages are reproducible.

## Style

* Python 3.10+, type hints on public functions, docstrings for modules/classes.
* Keep the core dependency-free; heavy optional tooling belongs in `scripts/`.
* Prefer explicit, boring code over clever one-liners in security-sensitive paths.
* Escape invisible/control characters before logging them (`escape_visible`).

## Pull request checklist

- [ ] Core still imports only the stdlib (`python scripts/check_core_deps.py`).
- [ ] All tests pass (`python -m unittest discover -s tests -t .`).
- [ ] New behaviour covered by positive **and** false-positive tests.
- [ ] Docs updated (README rule table / THREAT_MODEL severity / CHANGELOG).
- [ ] No secrets, tokens, personal data, or live exploit material in the diff.
- [ ] Demo/evidence artifacts regenerated if affected.

## Reporting security issues

Please report suspected vulnerabilities in `invisi-guard` itself privately via
GitHub's **Security → Report a vulnerability** (GitHub Security Advisories) on
this repository. Do not open a public issue for an unremediated security bug.
For vulnerabilities in *other* software (e.g. a model vendor), follow that
vendor's disclosure policy; this project's maintainers cannot coordinate on
their behalf.
