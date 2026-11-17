## Reproduction artifacts

Everything in this appendix lives under `report/snippets/` in the project
repository. The NuttX kernel sources themselves are **not** committed (see
`make sources`); the extracts are checked in so a reader can diff them
against the upstream tags or versions named in their headers, and the
fetched wpa_supplicant hostap files are checked in verbatim under
`snippets/upstream/`.

| Artifact | Content |
|---|---|
| `bt_uart_harness.c` | host harness for the Bluetooth UART receive path |
| `bt_uart_under_test.inc` | `btuart_read()` + `btuart_rxwork()`, verbatim from tag `nuttx-12.7.0` |
| `bt_uart_under_test_fixed.inc` | same region from tag `nuttx-12.9.0` (contains PR #16179) |
| `bt_uart_rxwork_pre_fix.c` | Listing 1: the vulnerable work function alone |
| `nuttx_net_bluetooth_sizes.h` | the real `BLUETOOTH_MAX_FRAMELEN` constants |
| `inode_unlink_harness.c` | host harness for the inode removal path |
| `inode_unlink_under_test.inc` | `inode_unlink()`, verbatim from tag `nuttx-12.9.0` |
| `krack_harness.c` | supplicant 4-way receiver model (vulnerable = wpa.c 2.3; fixed = current guard) |
| `sae_harness.c` | SAE reflection DoS model (vulnerable = sae.c 2.3; fixed = reflection guard) |
| `sae_derive_pwe_pre_dragonblood.inc` | the real SAE hunt loop, verbatim from wpa 2.3 sae.c |
| `../tools/sae_pwe_stats.py` | P-256 quadratic-residue oracle: the loop's iteration-count leak (seeded, N=1500) |
| `evidence_krack.txt`, `evidence_sae.txt` | the WPA traces cited in Chapters 3 and 5 |
| `upstream/wpa_23.c`, `upstream/wpa_cur.c` | hostap `wpa.c` 2.3 and current, as fetched (Debian source archive) |
| `upstream/sae_23.c`, `upstream/sae_cur.c` | hostap `sae.c` 2.3 and current, same |
| `Makefile` | builds both harnesses with `-fsanitize=address,undefined` |

### Build and run

```text
make            # builds the harness binaries
make run        # vulnerable ACL frame -> ASan stack-buffer-overflow
make fixed      # same frame, patched code -> "WARNING: H4 packet is too long"
make krack      # vulnerable 4-way receiver -> keystream reuse + recovery;
                # fixed model -> guard refuses the reinstall
make sae        # vulnerable receiver -> 5/5 reflection livelock;
                # fixed model -> guard drops the echo
python3 ../tools/sae_pwe_stats.py   # the hunt-loop leak measurement
```

Toolchain used: Apple clang with ASan/UBSan (macOS, arm64). The NuttX
extracts compile unchanged; only the NuttX types, Kconfig constants and
the UART/stack callbacks are stubbed. The WPA harnesses are models of
the upstream control structure (their code headers state which parts
mirror which file and version), not compiled upstream code.

### Sanitizer traces (frozen)

`evidence_acl.txt` — the 12.7.0 driver code, an `H4_ACL` frame declaring
`acl.len = 4096`, against a `BLUETOOTH_MAX_FRAMELEN` (79 byte) stack
buffer:

```
$ ./bt_uart_harness acl   # stack buffer = BLUETOOTH_MAX_FRAMELEN (79 bytes)
==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x00016d959bcf
WRITE of size 4096 at 0x00016d959bcf thread T0
    #0 ... in __asan_memcpy
    #1 ... in sim_read bt_uart_harness.c:73
    [32, 111) 'data' (line 47) <== Memory access at offset 111 overflows this variable
SUMMARY: AddressSanitizer: stack-buffer-overflow bt_uart_harness.c:73 in sim_read
```

`evidence_evt.txt` — an `H4_EVT` frame declaring `hdr.len = 255`, same
build:

```
$ ./bt_uart_harness evt
==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x00016d5a9bcf
WRITE of size 255 at 0x00016d5a9bcf thread T0
SUMMARY: AddressSanitizer: stack-buffer-overflow bt_uart_harness.c:73 in sim_read
```

`evidence_fixed.txt` — the 12.9.0 driver code, identical ACL input:

```
$ ./bt_uart_harness_fixed acl   # 12.9.0 code (PR #16179), same input
WARNING: H4 packet is too long
[test] rxwork returned
```

`evidence_inoderemove.txt` — the 12.9.0 `inode_unlink()` removing `/`:

```
$ ./inode_unlink_harness       # release config (DEBUGASSERT compiled out), ASan
[ftp] attacker session: DELE "/" on a filesystem service
      exposed over the network -> remove("/") -> inode_remove
[kernel] inode_remove("/") on the 12.9.0 pre-fix code...
runtime error: member access within null pointer of type 'struct inode'
==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010
==The signal is caused by a WRITE memory access.
==Hint: address points to the zero page.
    #0 ... in inode_unlink inode_unlink_under_test.inc:38
    #1 ... in inode_remove inode_unlink_harness.c
```

### Extraction procedure

The NuttX `.inc` files are byte slices of the tagged upstream sources:
from `static ssize_t btuart_read` to `static void btuart_rxcallback` in
`bt_uart.c`, and `inode_unlink` up to the next comment block in
`fs_inoderemove.c` — no other edits. The wpa `.inc` is the same slice
technique on `sae_23.c` (`sae_derive_pwe_ecc`), which the harnesses do
not compile (it needs the full `crypto_ec_point_*` surface) — it is
kept for reference next to the replica that measures it. Reviewers can
verify byte-for-byte equality against
`https://github.com/apache/nuttx/tree/nuttx-12.7.0` and
`nuttx-12.9.0` / `nuttx-12.10.0`, and against the checked-in
`snippets/upstream/` files. The extract script lives at
`report/snippets/extract_upstream.py`.

### Attempted and not reproduced

The `fs_rename` case (CVE-2025-48769) is documented in Section 3 (Case Study 2); the
harness produced ASan use-after-free reports, but only inside a model of
the FAT readdir lifetime we wrote ourselves, which we judged too weak to
publish as a reproduction. The negative result stands.

## Full harness sources

<!--raw-typst #snippet("bt_uart_harness.c", caption: [ "Full host harness for the Bluetooth UART case study."]) -->

<!--raw-typst #snippet("inode_unlink_harness.c", caption: [ "Full host harness for the inode removal case study."]) -->
