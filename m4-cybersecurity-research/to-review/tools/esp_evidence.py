#!/usr/bin/env python3
"""Derive the ESP-IDF evidence files checked in under lab/ from the JSON
fetched by `make sources-esp`."""
import json, os
lab = os.path.join(os.path.dirname(__file__), os.pardir, "lab")
for tag in ("v4.4", "v5.2"):
    f = os.path.join(lab, tag.replace(".", "") + "_src.json")
    d = json.load(open(f))
    paths = sorted(e["path"] for e in d["tree"]
                   if e["path"].startswith("components/wpa_supplicant/"))
    open(os.path.join(lab, "esp_%s_wpa_filelist.txt" % tag), "w").write("\n".join(paths))
    names = {os.path.basename(p) for p in paths}
    print(tag, "dpp:", any("dpp" in n for n in names),
          "dragonfly.c:", "dragonfly.c" in names, "sae_pk.c:", "sae_pk.c" in names)
d = json.load(open(os.path.join(lab, "v44_commits.json")))
hits = [c["sha"][:10] + " " + c["commit"]["author"]["date"][:10] + " "
        + c["commit"]["message"].splitlines()[0]
        for c in d if "reinstall" in c["commit"]["message"].lower()]
open(os.path.join(lab, "esp_v4.4_reinstall_commits.txt"), "w").write("\n".join(hits))
print("reinstall commits:", hits)
