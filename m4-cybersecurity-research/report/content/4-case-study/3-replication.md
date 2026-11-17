### Setup: why a host harness

The goal was to run the *actual shipped code* on crafted input, with the compiler proving the overflow. The realistic options were:

1. **QEMU + a real NuttX build with a Bluetooth UART attached.** The honest description of why we did not: no QEMU target in NuttX's tree attaches `bt_uart.c` to an emulated controller, the stock Bluetooth-enabled defconfigs are ESP32-family (xtensa toolchain), and standing up xtensa + QEMU + a synthetic HCI slave inside a single working session trades real evidence for plumbing risk. The emulator would also *change* the code under test (drivers are compiled against board glue).
2. **Host harness around the verbatim driver functions.** The driver's receive path is two self-contained functions (`btuart_read`, `btuart_rxwork`) plus a callback into the stack (`bt_netdev_receive`). Everything they touch is byte movement into a buffer. So we compile the upstream `.c` region verbatim, provide the NuttX types as the one-line stubs they effectively are, and replace the lower half with an in-memory UART and `bt_netdev_receive` with a sink. The code under test is not edited in any way — it is extracted from the tagged sources (Appendix A documents the extraction, and the same Makefile target rebuilds both binaries from checked-in upstream copies).

The harness (`snippets/bt_uart_harness.c`, two builds):

- vulnerable build: extracts from the `nuttx-12.7.0` tag;
- fixed build (control): the same extracts from the `nuttx-12.9.0` tag, which contains the fix;
- both built with `-fsanitize=address,undefined`.

One fidelity point the harness preserves: the 12.7 code sizes the stack buffer as `uint8_t data[BLUETOOTH_MAX_FRAMELEN]`, which expands to 79 bytes (`include/nuttx/net/bluetooth.h`); we reproduce that constant rather than the Kconfig default, because it is the buffer the real driver had on the stack.

### The attack, byte by byte

The harness feeds a crafted H4 stream and pumps `btuart_rxwork()`:

```c
  acl[0] = 0x02;                         /* H4_ACL  */
  acl[1] = 0xff; acl[2] = 0x0f;          /* handle  = 0x0fff          */
  acl[3] = 0x00; acl[4] = 0x10;          /* acl.len = 0x1000 = 4096   */
  memset(acl + 5, 0x41, sizeof(acl) - 5);
```

That is a seven-byte prologue and filler. The driver reads the type byte, reads the 4-byte ACL header, takes `acl.len = 4096`, and asks its own read loop to deposit 4096 bytes at `data + 5` — a buffer 74 bytes deep.

### Result

AddressSanitizer stops it exactly where predicted, and the fixed build eats the same input and logs the warning:

```
$ ./bt_uart_harness acl
==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x00016d959bcf
WRITE of size 4096 at 0x00016d959bcf thread T0
    #0 ... in __asan_memcpy
    #1 ... in sim_read bt_uart_harness.c:73        (the UART read loop)
    #2 ... in btuart_read bt_uart_under_test.inc:17
    #3 ... in btuart_rxwork bt_uart_under_test.inc:113
    [32, 111) 'data' (line 47) <== Memory access at offset 111 overflows this variable

$ ./bt_uart_harness_fixed acl
WARNING: H4 packet is too long
[test] rxwork returned
```

The event-frame path behaves the same on the vulnerable build: an `H4_EVT` frame declaring `hdr.len = 255` overflows the 79-byte buffer with a 255-byte write (`WRITE of size 255`). The 12.9 build sizes the buffer at `CONFIG_BLUETOOTH_UART_RXBUFSIZE` (2048) and guards only ACL frames, so the same event frame is accepted there without overflow -- accepted, note, not *validated*: the EVT branch of the fixed code still trusts `hdr->evt.len` up to 255, an echo of the same trust-the-length habit one release later. The full transcripts are in Appendix A.

### What the trace does and does not prove

It proves, for the real shipped function: attacker-chosen length flows to an unchecked `memcpy`-class copy into a fixed frame buffer. It does not prove code execution; on a Cortex-M target that requires knowing the frame layout (which varies by defconfig), and the CVE text stops at "may result in... arbitrary code execution". What we can add from the trace is that the corruption direction is *upward through the frame* (`data` is the only object in the frame, and the write runs past it into the saved registers of a work-queue task), which is the layout an exploit wants.

### Choosing the case studies

We picked CVE-2025-35003 for the primary slot because the vulnerable primitive is exactly one line of missing code, it is in a *driver* (where the application-can-validate-it doctrine of Section 3 plainly fails), and the fix is checkable. For a second case we initially targeted the `fs_rename` use-after-free (CVE-2025-48769); our reproduction attempt reached an honest failure (Appendix A, "attempted and not reproduced") because the aliasing that makes it dangerous runs through the FAT driver's readdir path, and modeling it faithfully without the real filesystem was the kind of harness that would have "proved" whatever it was written to prove. We kept the analysis (Case Study 2) and report the CVE-2025-48768 inode bug instead, which *is* trivially demonstrable in a host harness and whose root cause is the same doctrine: a missing check in a kernel primitive that trusted its caller.
