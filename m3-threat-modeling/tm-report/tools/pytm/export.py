#!/usr/bin/env python3
"""Export one pytm model for the report.

Usage: python export.py MODEL OUTDIR   (e.g. python export.py lv0 build/lv0)

Writes OUTDIR/dfd.dot and OUTDIR/pytm.json. The JSON groups findings by pytm
threat ID, and excluded findings by the assumption that excluded them.
It holds names only, no local paths, so the output is the same on any machine.
"""

import importlib
import json
import re
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


KIND = {
    "Actor": "External entity",
    "ExternalEntity": "External entity",
    "Process": "Process",
    "Datastore": "Data store",
}


def boundary_chain(element):
    """Boundaries enclosing an element, innermost first."""
    chain, b = [], element.inBoundary
    while b is not None:
        chain.append(b.name)
        b = b.inBoundary
    return chain


def export_elements(tm):
    """Every drawn element with its type and enclosing boundaries, for the report tables."""
    elements = [e for e in tm._elements if type(e).__name__ in KIND]
    return [
        {"name": e.name, "kind": KIND[type(e).__name__], "boundary": " / ".join(reversed(boundary_chain(e)))}
        for e in elements
    ]


def export_flows(tm):
    """Every flow in diagram order, with the boundaries it crosses."""
    flows = []
    for f in sorted(tm._flows, key=lambda f: f.order):
        src, dst = boundary_chain(f.source), boundary_chain(f.sink)
        crossed = [b for b in src if b not in dst] + [b for b in dst if b not in src]
        flows.append({
            "order": f.order,
            "name": f.name,
            "source": f.source.name,
            "sink": f.sink.name,
            "protocol": f.protocol,
            "crosses": crossed,
        })
    return flows


def rank_hints(tm):
    """Order numbers of flows that should not drive the left to right layout.

    Graphviz ranks every edge, so request and response pairs and store reads
    pull all external parties into one column and the diagram grows vertically.
    Responses and reads from data stores are drawn but left out of ranking,
    so the layout follows the request direction: user, console, host, Windows.
    """
    from pytm import Datastore

    return {
        f.order
        for f in tm._flows
        if f.responseTo is not None or isinstance(f.source, Datastore)
    }


def label_bottom(dot, names):
    """Move the label of the named boundaries to the bottom of their box.

    Graphviz does not keep edge labels clear of boundary labels, so a flow
    drawn across the top of a boundary can sit right on its name. A model lists
    the boundaries to fix in BOUNDARY_LABELS_BOTTOM.
    """
    for name in names:
        dot = re.sub(
            r"(\n(\s*))(label = <<i>" + r"(?:[^<]|<br/>)*?" + r"</i>>;)",
            lambda m: (m.group(1) + 'labelloc = "b";' + m.group(1) + m.group(3))
            if m.group(3).replace("<br/>", " ") == "label = <<i>" + name + "</i>>;"
            # Nested boundaries would inherit "b", so pin every other one to the top.
            else (m.group(1) + 'labelloc = "t";' + m.group(1) + m.group(3)),
            dot,
        )
    return dot


def patch_dfd(dot, loose=frozenset()):
    """Cosmetic fixes to pytm's Graphviz output, applied to every level.

    1. pytm wraps boundary names with a literal "\\n" inside an HTML label,
       which Graphviz prints as text. Replace it with a real line break.
    2. Draw boundaries in black instead of pytm's red, to match the
       monochrome Threat Dragon diagrams.
    3. and 4. Layout hints so every level reads left to right.
    """
    dot = re.sub(
        r"label = <<i>(.*?)</i>>;",
        lambda m: "label = <<i>" + m.group(1).replace("\\n", "<br/>") + "</i>>;",
        dot,
    )
    dot = dot.replace("color = firebrick2;", "color = black;")
    # 3. newrank lets Graphviz rank nodes across boundary clusters, so the
    #    clusters are laid out left to right instead of stacked vertically.
    dot = dot.replace("digraph tm {", "digraph tm {\n    newrank = true;", 1)
    # 4. Keep responses and store reads out of the ranking (see rank_hints).
    dot = re.sub(
        r'(\n\s*)label = "\((\d+)\) ',
        lambda m: (m.group(1) + "constraint = false;" if int(m.group(2)) in loose else "")
        + m.group(1) + 'label = "(' + m.group(2) + ") ",
        dot,
    )
    return dot


def main():
    name, out = sys.argv[1], Path(sys.argv[2])
    tm = importlib.import_module(name).tm
    tm.check()
    tm.resolve()
    loose = rank_hints(tm)
    out.mkdir(parents=True, exist_ok=True)
    module = sys.modules[name]
    dot = patch_dfd(tm.dfd(), loose)
    dot = label_bottom(dot, getattr(module, "BOUNDARY_LABELS_BOTTOM", []))
    (out / "dfd.dot").write_text(dot)
    result = {
        "model": tm.name,
        "findings": len(tm.findings),
        "excluded": len(tm.excluded_findings),
        "threats": group_findings(tm.findings),
        "assumptions": group_excluded(tm.excluded_findings),
        "elements": export_elements(tm),
        "flows": export_flows(tm),
    }
    (out / "pytm.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    main()
