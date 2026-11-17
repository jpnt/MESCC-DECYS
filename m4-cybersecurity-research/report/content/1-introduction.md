## Why NuttX, and why now

Embedded RTOS security research concentrates on FreeRTOS and Zephyr. NuttX gets less attention, which makes it an interesting target for a course project: the interesting question is not "is there a bug in NuttX" (there is always a bug) but "what does the NuttX project *do* about bugs, and does that answer change once NuttX is what a hundred million consumer devices boot?".

The second half of that question is why the timing matters. NuttX shipped in the Pebble watch and in a long tail of industrial panels, but its big consumer moment is Xiaomi's openvela (formerly Vela OS), the OS Xiaomi publishes for wearables, bands, speakers and appliances. Xiaomi's own documentation states the kernel "is built upon Apache NuttX" and describes POSIX conformance as the reason developers can port Linux software across with little effort. A generic memory-safety bug that only cost hobbyists a reboot now costs a vendor an OTA across a large fleet.

The first half is what a research project is for. NuttX publishes a short list of CVEs, and the list is short partly because disclosures have been sparse and partly because the project counts differently from, say, the Linux kernel. Between May and December 2025 four CVEs landed in one codebase alone (Bluetooth UART, a font-conversion tool, an example XML-RPC application, and two filesystem bugs), which tells you both that auditing is happening and that the audit surface is not being watched continuously by fuzzers.

## What we did

1. We enumerated the publicly disclosed NuttX CVEs from NVD and the Apache project's own security page, and classified them by subsystem, bug class and attack interface (Section 2).
2. We picked two CVEs to reproduce, chosen for demonstrability rather than severity: CVE-2025-35003 (buffer overflow in the Bluetooth UART driver) and CVE-2025-48768 (NULL write in the inode removal path). Sections 4 and 5 explain the choice and show the reproduction: the verbatim upstream functions compiled under AddressSanitizer with a small harness that replaces only the NuttX-specific glue.
3. We wrote a chapter on why NuttX is built the way it is, and where that design comes from in the Linux tradition, because the CVE list does not make sense without it (Section 3).
4. We compared NuttX's security engineering practice to Zephyr's, subsystem by subsystem: disclosure handling, fuzzing, static analysis, memory-protection posture (Section 6).
5. We close with what we think a critical-systems acquirer should take from all this (Sections 7 and 8).

## Scope and honesty notes

The reproductions are host-harness reproductions, not full-system ones. They run the exact code the project shipped, with exact-sized heap allocations, under the same compiler class (LLVM with ASan); they do not run NuttX on silicon, and they cannot demonstrate register-level control-flow hijack. Where we claim consequences beyond the sanitizer trace (arbitrary code execution, fleet impact), the claim comes from the vendor advisory, and we cite it. The section on which CVE we could *not* reproduce cleanly on this machine (CVE-2025-48769, the `fs_rename` use-after-free) explains why, because "what is hard to reproduce" is itself information about the bug.
