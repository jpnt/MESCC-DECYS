## What NuttX is

Developed under the assignment brief of Reliability and Cybersecurity (DECYS) [@brief], Apache NuttX is a real-time operating system with an emphasis on standards conformance and small footprint. The project describes it as scalable "from 8-bit to 64-bit microcontroller environments", governed primarily by POSIX and ANSI standards, with additional Unix and VxWorks-flavoured APIs where the standards do not reach or are not appropriate for deeply embedded use (notably `fork()`) [@nuttx-readme].

For a security analysis, three structural facts about the codebase matter:

**The kernel and the C library are the same binary.** NuttX merges what would be `vmlinux` and `libc` on Linux into one image, plus an optional application tree (`nuttx-apps`) that is compiled with it. Tasks are threads of a single scheduling universe, not processes with distinct address spaces. This is a deliberate portability choice; we return to it in Chapter 3.

**No MMU is required, and in the common build no MPU either.** NuttX runs on parts without a memory-management unit; the flat build shares one address space, and even the `CONFIG_BUILD_PROTECTED` MPU variant isolates applications from the kernel rather than from each other, so an app-side bug is still a whole-firmware bug. An MMU/protected mode exists (`CONFIG_BUILD_PROTECTED`, `CONFIG_BUILD_KERNEL`), but it is opt-in and per-architecture, and the widely used consumer configurations (including openvela-class devices) run flat or with light MPU regions.

**The networking stack is NuttX's own, not lwIP.** NuttX ships its native TCP/IP stack (`net/tcp`, `net/udp`, `net/ipv6`), its own Bluetooth stack (`wireless/bluetooth`), and can carry lwIP or uIP as alternatives; the case study in this report sits in the native Bluetooth path.

## The CVE record

Table 1 lists every CVE on the project's own security page, cross-checked against NVD records [@nuttx-security] [@nvd]. The list is short — eleven entries in roughly seven years, with a three-year gap (2022-2024) containing none — which should be read as *disclosure sparsity*, not as evidence of a secure codebase.

| CVE | Published | Subsystem | Bug class | Interface | Fixed in |
|---|---|---|---|---|---|
| CVE-2018-20578 [@cve-2018-20578] | 2018-12 | apps `netlib_parsehttpurl` | buffer issue | parsed URL | 7.27 |
| CVE-2020-1939 [@cve-2020-1939] | 2020-05 | apps `ftpd` | NULL pointer dereference | FTP service | 9.0.0 |
| CVE-2020-17528 [@cve-2020-17528] | 2020-12 | native TCP stack | OOB write (urgent pointer) | network | 9.1/10.0 line |
| CVE-2020-17529 [@cve-2020-17529] | 2020-12 | native TCP stack | OOB write | network | as above |
| CVE-2021-26461 [@cve-2021-26461] | 2021-06 | allocator (`malloc`/`realloc`/`memalign`) | integer wrap-around | any size input | 10.1 |
| CVE-2021-34125 [@cve-2021-34125] | 2023-03 | drone firmware on NuttX (Mantis Q, PX4 ≤1.11.3) | info exposure | — | — |
| CVE-2025-35003 [@cve-2025-35003] | 2025-05 | Bluetooth HCI/UART driver | unchecked length → stack buffer overflow | UART from BT controller | 12.9.0 |
| CVE-2025-47868 [@cve-2025-47868] | 2025-06 | `tools/bdf-converter` (host tool) | OOB write / heap overflow | crafted font file | 12.9.0 |
| CVE-2025-47869 [@cve-2025-47869] | 2025-06 | `apps/examples/xmlrpc` | hardcoded buffer size | remote stats params | 12.9.0 |
| CVE-2025-48768 [@cve-2025-48768] | 2025-12-31 | `fs/inode` (`inode_unlink`) | missing NULL parent check → root inode removal, DoS | network-exposed FS service (FTP) | 12.10.0 |
| CVE-2025-48769 [@cve-2025-48769] | 2025-12-31 | `fs/vfs` (`mountptrename`) | use-after-free via recursive rename | network-exposed FS service (FTP) | 12.11.0 |

Dates follow the oss-security/CVE-record announcements (NVD shows 2026-01-01 for the last two, a known NVD lag). Reading the table across the whole history, the shape of NuttX's exposure is: the network and the filesystem are the two remotely reachable attack surfaces, the Bluetooth driver added a third in 2025, and the allocator bug of 2021 shows what happens when the platform primitive itself is wrong. Several of the 2025 entries were fixed within one release cycle of each other, which we take up again in Chapters 4 and 7.

## How NuttX describes its own security posture

The project maintains a security page with an explicit "Not security vulnerabilities" section [@nuttx-security]. Its reasoning is that NuttX targets parts with kilobytes of memory, so generic checks would hurt size and speed, and therefore:

> "Function parameters and incoming data validation rests on the custom application/firmware developer."

It then lists what developers should be careful with: syscalls, pointers (NULL them before and after use), zero-initialising structures, user-controllable data, network data, dynamically allocated buffers. Issues with that stance are the subject of Chapters 3 and 7; here we note only that the page also documents the coordinated-disclosure route: reports go to `security@nuttx.apache.org` (auto-copied to `security@apache.org`), the Apache Security Team acts as CNA, fixes ship in the normal release cycle, and, unusually, fix commits must not reference their security nature until the announcement [@nuttx-security].
