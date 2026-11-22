## Reproduction artifacts

Everything in this appendix lives under `report/snippets/`, `tools/` and
`lab/` in the project repository. The `lab/` tree backs Chapter 3's
supply-chain section: the two official w1.fi release tarballs (sha256:
`wpa_supplicant-2.3` =
`eaaa5bf3055270e521b2dff64f2d203ec8040f71958b8588269a82c00c9d7b6a`,
`hostapd-2.6` =
`01526b90c1d23bec4b0f052039cc4456c2fd19347b4d830d1d58a0a6aea7117d`),
the ESP-IDF v4.4/v5.2 READMEs, the generated component file lists, the
guard-presence greps, the 2021 reinstall-commit record, the
release-to-release guard probe (`lab/esp_guard_probe.md`) and the
fix-commit timeline (`lab/esp_v4.4_timeline.md`) (regenerate
with `make sources-esp`); `tools/` holds `sae_pwe_stats.py` (seeded
leak measurement), `curve_check.py` (curve point count),
`esp_evidence.py`, `esp_timeline.py` (date-sorted tables from
`lab/v44_commits.json`, keys `sha`, `parents[].sha`,
`commit.author.date`, `commit.message`) and `esp_guard_probe.py`
(marker presence with line numbers over the fetched and pinned sources). The fetched hostap files are checked in verbatim
under `report/snippets/upstream/` (byte slices of the pinned w1.fi
releases in `lab/`, or of the current upstream tree) so a reader can
diff the models against the release files named in their headers.

| Artifact | Content |
|---|---|
| `krack_harness.c` | supplicant 4-way receiver model (vulnerable = official wpa.c 2.3 control structure; fixed = current guard) |
| `sae_harness.c` | SAE reflection-DoS model (vulnerable = 2.3 flow; fixed = reflection guard), real group law p=1009, #E=987 |
| `sae_derive_pwe_pre_dragonblood.inc` | the real SAE hunt loop, verbatim from the official 2.3 release |
| `upstream/wpa_23.c`, `upstream/wpa_cur.c` | hostap `wpa.c` at the official 2.3 release and current |
| `upstream/sae_2.3.c`, `upstream/sae_2.6_reflection_fixed.c`, `upstream/sae_cur.c` | hostap `sae.c` at 2.3 (pre-guard), 2.6 (guard present), and current |
| `evidence_krack.txt`, `evidence_sae.txt` | the traces cited in Chapters 3 and 5 |
| `lab/esp_v4.4_timeline.md` | date-sorted fix-commit table from `lab/v44_commits.json` (2021 GTK backports with parents; KRACK-subject window empty, reported as such) |
| `lab/esp_guard_probe.md` | per-snapshot guard marker presence with line numbers (upstream 2.3/2.6 anchors plus ESP-IDF v4.4/v5.2 sources) |
| `Makefile` | builds every model with ASan/UBSan; `make krack`, `make sae` run before/after |

### Build and run

```text
# from the module root (m4-cybersecurity-research/):
make krack # vulnerable receiver -> keystream reuse + recovery;
 # fixed model -> guard refuses the reinstall
make sae # vulnerable receiver -> 5/5 reflection livelock;
 # fixed model -> guard drops the echo
make report # typst compile
make slides # presentation deck
python3 tools/sae_pwe_stats.py # the hunt-loop leak measurement
python3 tools/curve_check.py # point-count of the harness curve
```

Toolchain used: Apple clang with ASan/UBSan (macOS, arm64). The WPA
harnesses are models of the upstream control structure (their code
headers state which parts mirror which file and version); the pinned
release files under `upstream/` and `lab/` are the diff targets.

### Sanitizer and run traces (frozen)

`evidence_krack.txt` and `evidence_sae.txt` are the full, verbatim
program output of the four model runs quoted in Chapters 3 and 5; the PWE statistics block in `evidence_sae.txt` is the seeded run of
`tools/sae_pwe_stats.py`. Reviewers can diff the quoted blocks against
these files; `make krack && make sae` regenerates the behaviour, and
the models' headers carry the mapping to the upstream guard strings
they reproduce (`report/snippets/upstream/wpa_cur.c` "Do not
re-install same PTK"; `sae_2.6_reflection_fixed.c` "evidence of a
reflection attack").

### The extraction procedure

The `.inc` and `upstream/` files are byte slices or whole files of the
pinned releases (`extract_wpa_upstream.py` documents the slice for the
hunt loop). Reviewers can verify equality against the tarballs in
`lab/` by sha256, and against `https://w1.fi/releases/`. The ESP-IDF
claims of Chapter 3 rest on GitHub-API listings and fetched sources
(`lab/esp_v*.txt`, `lab/v44_wpa.c`, `lab/v44_sae.c`), refetchable with
`make sources-esp` and derivable again with `tools/esp_evidence.py`.

## Full harness sources

The complete harness sources are listed below, byte-identical to
`report/snippets/`. The `.inc` extract is omitted for length; it is a
verbatim slice of the upstream file named in its header, reviewable
against `report/snippets/upstream/` and the pinned release hashes in
Chapter 3.

<!--raw-typst #snippet("krack_harness.c", caption: [ "KRACK supplicant-receiver model (vulnerable and fixed builds)."]) -->

<!--raw-typst #snippet("sae_harness.c", caption: [ "SAE reflection-DoS model (vulnerable and guarded builds)."]) -->
