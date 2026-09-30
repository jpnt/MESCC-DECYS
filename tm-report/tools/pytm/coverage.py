#!/usr/bin/env python3
"""Check that every pytm threat kept for a level is triaged in its 2-stride.md.

Usage: python coverage.py build/lv0/pytm.json analysis/lv0/2-stride.md
Exits non-zero and lists the threat IDs that 2-stride.md never mentions.
"""

import json
import sys
from pathlib import Path


def main():
    findings, stride = Path(sys.argv[1]), Path(sys.argv[2])
    ids = {t["id"] for t in json.loads(findings.read_text())["threats"]}
    text = stride.read_text()
    missing = sorted(i for i in ids if i not in text)
    if missing:
        sys.exit(f"{stride}: pytm threats not triaged: {', '.join(missing)}")


if __name__ == "__main__":
    main()
