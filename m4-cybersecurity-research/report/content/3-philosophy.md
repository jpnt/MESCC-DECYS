## NuttX: a Linux in miniature, deliberately

Gregory Nutt started NuttX in the mid-1990s with an explicit goal: a kernel small enough for microcontrollers that still looked like Unix to an application programmer. The result is a system that adopted the Linux *programming model* — POSIX threads, file descriptors for everything, `ioctl`, sockets, procfs — without adopting the Linux *kernel architecture*. Understanding which parts of the philosophy travelled and which stayed behind is the key to reading NuttX's bug history, because every design decision below has a security consequence that shows up in at least one CVE we study.

## What was inherited from the Linux tradition

**Unified kernel/libc namespace.** On Linux, user code cannot call kernel functions directly; it crosses a boundary via syscalls. NuttX discards the boundary: "user space" code calls `nxsem_wait()` or `fs_heap_malloc()` as ordinary C. The project describes this as why the same source tree is both kernel and library. Linux-ABI compatibility is preserved at the *source* level (a POSIX program recompiles), not at the *binary/isolation* level.

**Everything is a file, drivers as inodes.** The NuttX inode tree (Case Study 2's scene of the crime) is the direct ancestor: device nodes, mount points and pseudo-directories in one tree, with driver operations as a function table per inode. The 2025 filesystem CVEs are bugs in exactly this inheritance.

**Process/thread model with shared address space semantics.** NuttX "tasks" are scheduler-visible threads over one address space (flat mode), or per-process spaces if the MMU build is configured. The default is the former, and it is the one consumer builds use.

**A shell and a network server farm in the base image.** `nsh`, telnetd, ftpd and friends ship in-tree; the same Linux distribution instinct ("the tools are part of the system") that made 1990s Linux boxes attackable is why NuttX's advisory text keeps pointing at "FTP exposed over the network".

## What was deliberately *not* inherited

**No MMU requirement.** Linux assumes an MMU; NuttX assumes it away. This is the single most security-relevant divergence: on the flat build there is no virtual-memory separation, so the kernel's entire "exploit mitigation" story in the Linux sense (KASLR, SMAP/SMEP, user/kernel page tables) is structurally absent, not merely disabled.

**No user-space memory protection at all by default.** With an MPU available on Cortex-M-class parts, NuttX can offer `CONFIG_BUILD_PROTECTED`: kernel and apps in separate regions, apps trapped through a thin syscall shim. It exists, is real, is per-architecture, and the mainstream consumer configurations do not enable it because it costs RAM/flash and constrains the application model (no arbitrary pointers across the boundary).

**No fork.** The README calls this out explicitly: `fork()` is "not appropriate for deeply-embedded environments". NuttX keeps `vfork` and `posix_spawn` shapes. Beyond footprint, this forecloses the copy-on-write process model that makes Unix isolation cheap, which is part of why the flat model was acceptable.

**No dynamic module loading as a rule.** Fewer moving parts than Linux; also fewer mitigations.

## The security price of the philosophy, stated plainly

On an MMU OS, a bug in a *driver* is contained by *whom the driver is for*: it corrupts one address space. In flat NuttX, a driver bug is a whole-firmware bug; the CVE-2025-35003 stack overflow does not "crash the Bluetooth app", it walks the return addresses of whatever frame the RX work queue uses. And the project's own guidance — validate inputs in the application — presumes the application is the only untrusted input source. In the case studies, the untrusted input is a UART byte stream from a $2 module and a network packet into a stock daemon; the application author never sees those APIs.

This is why the 2021 allocator CVE (CVE-2021-26461, integer wrap in `malloc`/`realloc`/`memalign`) is the one that best expresses the doctrine's failure mode: when the platform primitive is wrong, *every* consumer — including correct, carefully validating applications — inherits the bug. The mitigation text in such cases is "upgrade the kernel", which is exactly what a small-project release process is worst at delivering.

## The other reading: this is also a coherent engineering position

It would be cheap to present NuttX as careless. It is not. The design optimises for the 8-bit and deeply constrained market it was built for, where MPU protection, separate address spaces and defensive copies are *not affordable in kilobytes*, and where "no isolation anyway" is honest about the silicon. Many of the same trade-offs exist on Linux in the embedded sense (single-function appliances run as root, everything in one container, no seccomp); NuttX simply refuses to pretend otherwise, and documents its assumptions in the security page instead of leaving them implicit. Our comparison target, Zephyr, made the *opposite* bet (MPU-first, user-mode-first, heavier footprint) and pays for it with a different CVE profile, not a smaller one (Section 6). The report's conclusion is not "NuttX is insecure" but "NuttX's philosophy is only safe at the low end of its scale, and its marketing has outgrown it".
