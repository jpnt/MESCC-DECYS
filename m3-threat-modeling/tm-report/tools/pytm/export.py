#!/usr/bin/env python3
"""Export one pytm model for the report.

Usage: python export.py MODEL OUTDIR   (e.g. python export.py lv0 build/lv0)

Writes OUTDIR/dfd.dot and OUTDIR/pytm.json. The JSON groups findings by pytm
threat ID, and excluded findings by the assumption that excluded them.
It holds names only, no local paths, so the output is the same on any machine.
"""

import importlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

SEVERITY = ["Very High", "High", "Medium", "Low", "Info"]


def group_findings(findings):
    threats = {}
    for f in findings:
        t = threats.setdefault(
            f.threat_id,
            {"id": f.threat_id, "name": f.description, "severity": f.severity, "targets": []},
        )
        if f.target not in t["targets"]:
            t["targets"].append(f.target)
    return sorted(
        threats.values(),
        key=lambda t: (SEVERITY.index(t["severity"]) if t["severity"] in SEVERITY else len(SEVERITY), t["id"]),
    )


def group_excluded(findings):
    assumptions = {}
    for f in findings:
        a = assumptions.setdefault(
            f.assumption.name,
            {"name": f.assumption.name, "description": f.assumption.description, "threats": [], "targets": []},
        )
        if f.threat_id not in a["threats"]:
            a["threats"].append(f.threat_id)
        if f.target not in a["targets"]:
            a["targets"].append(f.target)
    for a in assumptions.values():
        a["threats"].sort()
    return list(assumptions.values())


def main():
    name, out = sys.argv[1], Path(sys.argv[2])
    tm = importlib.import_module(name).tm
    tm.check()
    tm.resolve()
    out.mkdir(parents=True, exist_ok=True)
    (out / "dfd.dot").write_text(tm.dfd())
    result = {
        "model": tm.name,
        "findings": len(tm.findings),
        "excluded": len(tm.excluded_findings),
        "threats": group_findings(tm.findings),
        "assumptions": group_excluded(tm.excluded_findings),
    }
    (out / "pytm.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
