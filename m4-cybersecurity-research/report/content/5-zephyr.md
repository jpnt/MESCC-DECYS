## Why Zephyr

Zephyr is the right comparison for NuttX: same problem domain (constrained MCUs), same open-source governance under a foundation (Linux Foundation vs Apache), broadly overlapping hardware ambitions, and an explicit security program that states its practices publicly. If NuttX's CVE sparsity and "validate it yourself" guidance reflect a culture, Zephyr's documentation shows the alternative culture at roughly the same silicon cost. This section compares practice, not product superiority; NCC Group's 2020 assessment of Zephyr (25 vulnerabilities, several remotely reachable, plus user-to-kernel escalation paths) is a reminder that Zephyr's process produced disclosures, and the absence of disclosures elsewhere is not evidence of virtue [@ncc-zephyr].

## Disclosure handling

| Aspect | NuttX | Zephyr |
|---|---|---|
| Route | `security@apache.org`, Apache Security Team policy; ASF CNA assigns CVEs [@nuttx-security] | dedicated security page, `sectech@lists...` report intake, embargoed advisories via GitHub, CVEs through Linux Foundation CNA [@zephyr-sec] |
| Handling team | no standing NuttX security team; fixes are written by whoever reviews the PR | Security Triage Team + Technical Security Committee with named members, documented rotation, weekly meetings [@zephyr-sec] |
| Advisories | CVE list on one docs page, release notes; no embargo mechanism of its own | GHSA advisories with fixed publication dates, affected-version matrices, exploitability notes |
| Observed cadence | 11 CVEs in ~7 years; the 2025 cluster arrived within months of one another [@nuttx-security] | a steady, published advisory flow (GitHub security advisories for the zephyr repo) [@zephyr-sec] |
| Response artifacts | fix PR plus CVE; testing lines list a board name (e.g. "esp32c6-xiao:usbnsh") | fix + advisory + CVSS + credits; where found by fuzzing, a reproducer is attached |

The structural difference is *institutional memory*: Zephyr's security team reads every bug report looking for the security-shaped ones. NuttX relies on the Apache CNA pipeline, which numbers and publishes what it is handed but does not look for bugs. In our case studies that showed: CVE-2025-48769's fix comment says "Patch provided by @richyliu" — the project accepted and shipped an external patch, credited him, and never had a team that would have gone looking for sibling bugs in the same loop before the reporter did.

## Testing and fuzzing

Zephyr runs unit tests (Twister) in CI and maintains in-tree fuzzing documentation and samples: libFuzzer/AFL++ integration on the native\_sim board is an official sample, and the project has published a tutorial on AFL++/Renode application fuzzing on its blog [@zephyr-fuzz]. Notably, Zephyr is *not* an OSS-Fuzz project today either: the integration request (google/oss-fuzz\#15486) has been open since 2026 without landing [@ossfuzz-zephyr-pr], and neither project appears in the OSS-Fuzz projects tree [@ossfuzz]. The difference is therefore one of *invited* versus *uninvited* tooling: Zephyr ships fuzzing harnesses developers are pointed at, NuttX ships none.

We could not find a NuttX project in the OSS-Fuzz repository at the time of writing (no `projects/nuttx` in google/oss-fuzz) [@ossfuzz]. NuttX CI builds a large defconfig matrix on every PR, which is a compile-coverage discipline (arguably better than Zephyr's, given the board count), and the project added `tools/memcheck`-style static checks over the years. But there is no continuous dynamic analysis of the runtime: the TCP urgent-pointer CVEs of 2020 and the Bluetooth CVE of 2025 sit in exactly the parser-shaped code that syzkaller-class harnesses find within minutes elsewhere. When we searched for NuttX in the academic fuzzing literature (Section 2), the same absence appeared: RTCON evaluates Zephyr, RIOT, FreeRTOS and ThreadX; NuttX is not in the target set [@rtcon].

## Language, mitigations, and architecture

Zephyr ships, by default, more of what Linux calls "exploit mitigations": an MPU-based userspace/kernel split on Cortex-M (`CONFIG_USERSPACE`), stack canaries, `CONFIG_HW_STACK_PROTECTION`, write-xor-execute memory regions, and a documented hardening Kconfig list. NuttX offers `CONFIG_BUILD_PROTECTED`/`CONFIG_BUILD_KERNEL` equivalents but defaults to a flat image (Section 3), and the mitigation posture is a build option vendors must opt into, per board, at the cost of RAM.

Zephyr additionally maintains a formal secure-coding standard, MISRA-oriented tooling (Project Guard static analysis, Coverity on the tree), and function-safety certifications (IEC 61508 via commercial variants). NuttX's static story: the Apache license compliance checks, CI builds, and periodic third-party audits, but no published static-analysis badge. On the language question, neither tree is memory-safe, but the Zephyr ecosystem has visible experimentation (Rust driver efforts) where NuttX's equivalent (rust-for-nuttx work in openvela forks, e.g. the open-vela/nuttx "Rust enhance" project [@openvela]) lives in vendor forks, not upstream.

## What NuttX does better

To keep the comparison honest: NuttX's flat, single-repository build is genuinely simpler to audit as a whole — one `make`, one config language, board support in-tree; a reviewer of a shipped image can rebuild it bit-for-bit without the west-manifest dependency graph Zephyr requires. Its POSIX completeness (the surface area we inherit from Linux, including pthreads and sockets) is broader than Zephyr's, which means applications carry fewer home-grown parsing wrappers — fewer `memcpy` sites in vendor code is a real security property, and it is why Linux-portable code keeps landing on NuttX. Its release cadence is fast (12.9→12.13 in months), and the 2025 fixes all shipped in the very next release with tight review. The gap this report measured is not engineering competence at any single point; it is the *continuous* layer — a team whose job is to look, and tools that look even when humans don't.
