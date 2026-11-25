"""Generate docs/demo.html and docs/demo_revealed.html (deterministic demo pages).

Usage::

    python scripts/build_demo.py [--out-dir docs]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from invisi_guard.demo import write_demo_html  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", default=str(ROOT / "docs"))
    args = parser.parse_args()
    out_dir = Path(args.out_dir)
    interactive = write_demo_html(out_dir / "demo.html")
    revealed = write_demo_html(out_dir / "demo_revealed.html", auto_reveal=True)
    for target in (interactive, revealed):
        print("wrote %s (%d bytes)" % (target, target.stat().st_size))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
