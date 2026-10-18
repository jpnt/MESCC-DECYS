#!/usr/bin/env python3
"""Check that every pytm threat kept for a level is triaged in the report.

Usage: python coverage.py build/lv0/pytm.json report/data/pytm-triage.yaml
Exits non-zero and lists the threat IDs that the triage file never mentions.
"""

import json
import sys
from pathlib import Path


def main():
    findings, triage = Path(sys.argv[1]), Path(sys.argv[2])
    ids = {t["id"] for t in json.loads(findings.read_text())["threats"]}
    text = triage.read_text()
    missing = sorted(i for i in ids if i not in text)
    if missing:
        sys.exit(f"{findings}: pytm threats not triaged in {triage}: {', '.join(missing)}")


if __name__ == "__main__":
    main()
