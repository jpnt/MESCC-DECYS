#!/usr/bin/env python3
"""Date-sorted fix-commit timelines for ESP-IDF releases' wpa_supplicant
component, derived deterministically from the fetched GitHub API records
lab/<short>_commits.json (`make sources-esp`; keys read per commit:
`sha`, `parents[].sha`, `commit.author.date`, `commit.message`). Two
windows per tag: KRACK-family subjects (reinstalled|re-install, the
wording of the 2017-2018 upstream CVE-2017-13077..13087 batch) and every
commit touching group-key reinstallation. One file per tag,
lab/esp_<tag>_timeline.md; stdout is the same text. If no row in the
window matches a keyword set, the section says so: absence in this
record is itself reported, not silently dropped."""
import json, os, sys, argparse

KW_REINSTALL = ("reinstalled", "re-install")
KW_GROUPKEY = ("reinstall", "group key")

def first_line(s):
    return s.splitlines()[0].strip() if s else ""

def rows(path):
    out = []
    for c in json.load(open(path)):
        msg = c["commit"]["message"] or ""
        out.append({
            "sha": c["sha"],
            "short": c["sha"][:10],
            "date": c["commit"]["author"]["date"],
            "subject": first_line(msg),
            "parents": [p["sha"][:10] for p in c.get("parents", [])],
            "merge": msg.lstrip().startswith("Merge branch"),
            "subj_l": first_line(msg).lower(),
            "text_l": msg.lower(),
        })
    return out

def section(rs, keywords, label, subject_only=False):
    key = "subj_l" if subject_only else "text_l"
    hits = [r for r in rs if any(k in r[key] for k in keywords)]
    hits.sort(key=lambda r: (r["date"], r["sha"]))
    lines = ["#### %s" % label, "",
             "| Date | Short SHA | Parent(s) | Commit subject |",
             "|---|---|---|---|"]
    if not hits:
        lines.append("| (none) | | | no commit in the fetched window matches %s |"
                     % " / ".join(keywords))
    for r in hits:
        subj = r["subject"] + (" (merge commit)" if r["merge"] else "")
        lines.append("| %s | `%s` | %s | %s |"
                     % (r["date"], r["short"],
                        ", ".join("`%s`" % p for p in r["parents"]) or "-",
                        subj))
    return lines, hits

def build(tag, src):
    short = os.path.basename(src).replace("_commits.json", "")
    rs = rows(src)
    lo = min(r["date"] for r in rs)
    hi = max(r["date"] for r in rs)
    head = [
        "## ESP-IDF %s `components/wpa_supplicant` fix-commit timeline" % tag,
        "",
        "From `lab/%s_commits.json` (GitHub API" % short,
        "`commits?sha=%s&path=components/wpa_supplicant&per_page=100`;" % tag,
        "regenerate + refetch with `make sources-esp`).",
        "Sorted by author date then SHA. The fetched page covers %s..%s"
        % (lo[:10], hi[:10]),
        "(%d commits): the most recent page-1 window only, so a 2017-2018" % len(rs),
        "KRACK-era upstream fix date could not appear even if %s carried" % tag,
        "one. Keys: `sha`, `parents[].sha`, `commit.author.date`,",
        "`commit.message` (first line = subject).",
        "",
    ]
    s1, h1 = section(rs, KW_REINSTALL,
                     "PTK/GTK reinstallation (KRACK-family subjects)",
                     subject_only=True)
    s2, h2 = section(rs, KW_GROUPKEY, "Group-key reinstallation")
    return "\n".join(head + s1 + [""] + s2 + [""]), len(rs), len(h1), len(h2)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default=None, help="single tag, e.g. v4.4")
    a = ap.parse_args()
    here = os.path.dirname(os.path.abspath(__file__))
    lab = os.path.join(here, os.pardir, "lab")
    tags = [a.tag] if a.tag else ["v4.4", "v5.2"]
    for tag in tags:
        short = "v" + tag.replace("v", "").replace(".", "")
        src = os.path.join(lab, "%s_commits.json" % short)
        out = os.path.join(lab, "esp_%s_timeline.md" % tag)
        if not os.path.exists(src):
            continue
        text, n, m1, m2 = build(tag, src)
        open(out, "w").write(text)
        sys.stdout.write(text)
        print("[esp_timeline] %s: %d rows, %d+%d matched -> %s"
              % (tag, n, m1, m2, os.path.relpath(out, lab)))

if __name__ == "__main__":
    main()
