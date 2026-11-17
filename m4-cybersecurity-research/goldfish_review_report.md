# Goldfish review report — round 1

Target: report/content/5-analysis/1-wpa-mechanisms.md (lines 1-131)
Reviewers: egm-zoom-out (completed), egm-comprehension (completed), egm-implementation-readiness (completed)

## Findings (aggregated)

### CONTESTED / RECORDED (no fix)

**F-R1-14 [RECORDED] impl Major#15: refs.bib wpasrc url w1.fi vs prose "Debian archive"**
Debian archive is the provenance; w1.fi is the canonical project home; both true.

**F-R1-15 [RECORDED] impl Major: harness guard regressions "pass silently"**
make krack/sae run the binaries and check exit codes; the grep-on-output suggestion would
re-check traces (Appendix A already freezes them). Accepted as-is.

### PROPOSE FIX (pending approval)

**F-R1-01 [🔴 Blocker] L113** "Compare Section 2's NuttX CVE record" → CVE record lives in Chapter 2 (background) — but the case-study credit material is Chapter 3. Ref → "Chapter 2's NuttX CVE record". [zoomout#1]

**F-R1-02 [🔴 Blocker] L128-131** Closing paragraph claims Sections 4/5 name the injection-hardware obstacle; §6 doesn't. → point at "Section 5's 'What we could not do'", drop "every one of". [zoomout#2; comprehension#5]

**F-R1-03 [🟡 Major] L1-15** Citation-cluster typo: "in a small model, [@krack] [@krack-site]" duplicates earlier citations; sentence 125 chars. → remove stray comma/cluster, split paragraph. [zoomout#7; comprehension#11; impl#14]

**F-R1-04 [🟡 Major] L21 / L28-34 / L38** "ten lines" overstates; quoted block omits interleaved supplicant lines; "same nonce" — only PN is reused in the model. → "a guard of a few lines", block marked excerpt (or paste full trace), "same PN, same key". [impl#5,#7; comprehension#17]

**F-R1-05 [🟡 Major] L29 / evidence_krack.txt** Harness cannot emit `...ABCD1234567890` (pt2 32-byte truncation vs evidence file 35 chars). → lengthen harness buffer/token, regenerate trace, keep section quote consistent. [impl#4]

**F-R1-06 [🟡 Major] L46-49** `lora_pkt_fwd` listed in apps/wireless but not in fetched nuttx-apps releases/12.9 tree. → drop it (or cite the master-only path). [comprehension#3; impl#11]

**F-R1-07 [🟡 Major] L47-53** Claims "no real AP secret ever enters the key" — harness never runs key_tag() to prove it. → wire key_tag() assertion into harness (both confirms computed; assert mismatch), or soften prose. [impl#6]

**F-R1-08 [🟡 Major] L56-57** "order 1024" is wrong: #E(F_1009) = 987 (= 3×7×47). Generator still works; ORD wrong → modn() wrong scalar ring. → B=749, ORD=987 verified: same 5/5 + guard-drop. [impl#8]

**F-R1-09 [🟡 Major] L61-72 / tools** Stats quoted from an unseeded run; reproducible spread 0.052-0.072; script prints a tail the quote truncates silently. → seed + fixed histogram (c=4..7), re-quote, state N=1500. [impl#1; comprehension#2; zoomout#4]

**F-R1-10 [🟡 Major] L61-62** "measured it against the real loop rather than model it" — measurement ran on a Python replica; the verbatim .inc cannot compile standalone. → rephrase: "measured against a control-flow-faithful replica of the real loop (extract kept verbatim for reference)". [impl#3]

**F-R1-11 [🟡 Major] L81-105 (repo)** "we fetched both" ESP-IDF evidence: only artifact captured was a 404 page; sources not in work/ or Makefile. → add work/wpa_23.c etc + esp README fetch rules to Makefile `sources`; delete wpa_readme_esp.txt; cite v4.4/v5.2 tag URLs not master. [comprehension#1; impl#2,#12,#15]

**F-R1-12 [🟡 Major] L84-88** Heading "Where this code lives, and where NuttX's lives" promises a location NuttX lacks. → "— and why NuttX's does not". [comprehension#20]

**F-R1-13 [🟡 Major] L113+ (repo, appendix)** Section/Chapter numbering stale in appendix + other files' trace pointers; extract line-counts wrong ("130 and 45" vs 132/53); "builds both harnesses"; report/appendix path wrong; poc-source embeds 1 of 3 harnesses. → fix all. [impl#10,#13]

**F-R1-16 [🟢 Nit] repo** extract_bt_uart.py not in repo yet referenced by top Makefile; make clean omits 4 WPA binaries + dSYM; .PHONY lacks krack/sae. → fix Makefile, keep script in snippets/. [impl#9,#13]

**F-R1-17 [🟢 Nit] L4,12-13,20,54,66,77,105,117** gloss supplicant at first use, INSTALL bit → Install bit, Msg4 → Message 4, "the papers" → "the Dragonblood paper", "nobody can state" → verifiable form, "Debian's audited" → "versioned", five rounds → fixed count, p vs n parenthetical, CVE subsets we test. [comprehension#4,#6,#13,#14,#15,#16,#18,#19]

**F-R1-18 [🟢 Nit] L56-59** Add clause: small curve is a state-machine vehicle, not a real-curve cost estimate. [zoomout#8]

**F-R1-19 [🟡 Major, cross-file] zoomout#5/#6** Supply-chain evidence duplicated (here + 6-implications.md L40-55); offline-password consequence asserted but undemonstrated in this section; honest-limits re-argued 3× elsewhere. → de-duplicate implications; add one sentence quantifying the offline gain (paper's figure, cited); cut limits to a pointer.
