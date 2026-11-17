## CVE-2025-48768: removing the filesystem root

The second case is small enough to state completely. `fs/inode/fs_inoderemove.c` unlinks an inode from the pseudo-filesystem tree before its caller frees it. The search result for the root inode `/` is `desc.parent == NULL`, because the root has no parent. The pre-fix code assumed it always had one:

```c
      else
        {
          DEBUGASSERT(desc.parent != NULL);
          desc.parent->i_child = inode->i_peer;
        }
```

`DEBUGASSERT` compiles away unless `CONFIG_DEBUG_ASSERTS` is on, which it is not in release builds. So on the default configuration the line becomes an unconditional write through a NULL pointer: `*(uintptr_t *)offsetof(struct inode, i_child) = ...`.

The fix (PR apache/nuttx#16437, "fs/inode: Fix inoderemove when removing an inode without parent", opened by Alberto Garcia, patch authored by Richard Liu) replaces the assumption with a check and an error path: if `desc.parent == NULL`, the unlink fails and returns no inode, so the caller's `inode_remove()` reports `ENOENT` and nothing is freed [@pr-16437]. The project's security page credits the finder and remediation developer of both 2025 filesystem CVEs to one outsider, Richard Jiayang Liu, with NuttX committer Tomek Cedro coordinating [@nuttx-security]. The advisory (CVSS 6.5 DoS) names the same attacker we discussed: users of filesystem services with write access exposed over the network, i.e. the companion-tree FTP daemon (apps/netutils/ftpd) [@cve-2025-48768].

## Reproduction

Same technique: the verbatim 12.9.0 `inode_unlink()` is compiled into a harness (`snippets/inode_unlink_harness.c`) with a two-inode tree (root plus one child) and a search that returns the root with `parent == NULL` for the path `"/"`. Running `inode_remove("/")` with ASan on:

```
$ ./inode_unlink_harness
[ftp] attacker session: DELE "/" on a filesystem service
      exposed over the network -> remove("/") -> inode_remove
[kernel] inode_remove("/") on the 12.9.0 pre-fix code...
runtime error: member access within null pointer of type 'struct inode'
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010
==The signal is caused by a WRITE memory access.
==Hint: address points to the zero page.
    #0 in inode_unlink inode_unlink_under_test.inc:38
    #1 in inode_remove inode_unlink_harness.c
```

Address `0x10` is exactly `offsetof(struct inode, i_child)` in the real header order (`i_parent`, `i_peer`, `i_child`): the store is where the kernel meant to write the parent's child link, aimed at the zero page. On a target with a data MPU or an MMU this is a clean crash — denial of service, matching the advisory's rating. On a flat, no-MMU build, which Chapter 3 argued is the common configuration, writes to `0x10` do not fault: they scribble on the interrupt vector table area of flash-RAM aliasing on some architectures, or on low RAM globals on others. The advisory hedges exactly this: the NULL dereference is "handled differently depending on the target architecture".

## Why this bug and the first one rhyme

Both are checks that exist at the *system boundary* on Linux and do not exist inside NuttX's single address space:

- The Bluetooth bug trusts a length field arriving from a hardware component the host cannot distinguish from an attacker. Linux's Bluetooth stack is also C, but the subsystem is fuzzed continuously from user-facing transports (syzkaller's Bluetooth coverage is an established part of kernel fuzzing), and the vulnerable code runs at least inside privilege and address-space boundaries.
- The inode bug trusts a structural property of its own caller ("an inode always has a parent, except the root, and nobody removes the root"). Linux's `d_delete`/`shrink_dentry` paths cannot be driven from userspace into removing `/` because the VFS refuses at a higher layer; in NuttX the refusal was the one `DEBUGASSERT` nobody shipped.

Both were found by reading, not by fuzzing; both were fixed within days of reporting; neither had a public PoC before our harness compiled one (the PR text describes STM32 and ESP32-C3 hardware tests but ships no reproducer). For a project with 40 hours per member available, that last point is the practical takeaway: two person-days each of static reading of boundary functions produced reproducible CVEs, on an OS with no continuous fuzzing watching the same code.

## Attempted and not reproduced: CVE-2025-48769

For completeness: the `fs_rename` use-after-free fix (PR #16455 [@pr-16455]) removes a `goto next_subdir` loop that, on a second iteration, freed the `subdir` buffer through `tmp` while another name (`newrelpath`, and in the kernel the search descriptor's relpath) still aliased the same heap block — "single buffer use by two different pointer variables" in the advisory's words [@cve-2025-48769]. We built a harness around the verbatim loop with a heap-aliasing filesystem model and observed ASan use-after-free reports, but only under a model of `stat()`/`unlink()` heap lifetime we invented; the real aliasing runs through `readdir` buffers and the FAT driver's directory-entry blocks, which we could not reproduce faithfully without building the actual filesystem in QEMU. We report that honestly: our claim about CVE-2025-48769 rests on the fix diff and advisory, not on our traces.