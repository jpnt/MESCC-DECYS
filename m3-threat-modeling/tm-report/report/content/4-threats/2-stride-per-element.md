# Threat analysis

## STRIDE per element

Every element of the two level 1 diagrams was examined against each STRIDE category that applies to its type. Level 1 was chosen as the working level because it is the first one that shows every boundary: the network between console and host only appears there, and the process boundaries of the bootable mode too. Level 0 hides those crossings, and level 2 adds detail that changes where a threat is located but not which threats exist. Level 2 is still used, to place each threat on the internal part that would have to defend against it (the "Level 2" column of the registers).

The two matrices below show the result. A cell lists the threats found for that element and category, "none" means the combination applies but no credible threat was found, and "n/a" means the category does not apply to that type of element.

<!--raw-typst #register.stride-matrix("normal", [STRIDE per element, level 1 normal mode]) <tbl-matrix-normal> -->

The "none" cells in the normal mode are deliberate. Flows 5, 7 and 8 (the host's queries to Windows and the registry data that comes back) can only be altered by code that already controls the server's kernel, which is the forged answer threat T03, recorded once as spoofing of the Windows entities. The same holds for the service control flows 9 and 10, which carry no data worth reading or forging. Denial of service on the operator's own keyboard and screen (flows 1 and 2) adds nothing beyond a console that is unavailable (T11).

<!--raw-typst #register.stride-matrix("boot", [STRIDE per element, level 1 bootable mode]) <tbl-matrix-boot> -->

In the bootable mode many threats of the normal mode disappear with the network, and the matrix fills up instead around the boot media, the results drive and the operator's keyboard, which in this mode belongs to the compromised machine.

## Threat register

Each threat found is described once, under the element it mainly concerns. The register also gives where the threat sits in the level 2 diagram, the assets at stake, and the corresponding entries in public catalogues: MITRE ATT&CK [@attack] for attacker techniques and CWE [@cwe] for weaknesses. The last line of each entry shows which pytm findings matched it, or "found by hand" when the tool proposed nothing similar.

<!--raw-typst #register.register("normal", [Threat register, normal mode (including threats shared with the bootable mode)]) <tbl-register-normal> -->

The threats shared by both modes <!--raw-typst #[(#register.inherited("boot"))]--> were listed above and are not repeated. The register for the bootable mode therefore lists only what is new in that mode.

<!--raw-typst #register.register("boot", [Threat register, bootable mode (threats specific to this mode)], only: "new") <tbl-register-boot> -->

## Threat library

pytm proposes candidate threats by matching every element of the model against its threat library, which is largely derived from CAPEC [@pytm] [@capec]. The candidates were triaged by hand: kept when they matched a threat as they stood, merged when they were one technique within a broader threat, and rejected with a reason when they did not apply. The full triage is in Appendix A.

The tool and the manual analysis complemented each other. pytm was thorough on generic weaknesses, such as memory safety in the C++ host and the lack of protection on every flow. It had nothing to say about the threats most specific to an integrity checker, because those depend on what the data means rather than how it moves. <!--raw-typst #register.hand-only-count()--> of the threats in the register were found by hand only <!--raw-typst #[(#register.hand-only())]-->, among them the blind acceptance of a new baseline (T39), the rollback of an old baseline (T22) and the use of hash collisions to hide a change (T20).
