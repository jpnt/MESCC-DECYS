## Reproduction artifacts

Everything in this appendix lives under `report/snippets/`, `tools/`
and `lab/` in the project repository. The `lab/` tree backs Chapter 3's
supply-chain section: the two official w1.fi release tarballs (sha256:
`wpa_supplicant-2.3` = `eaaa5bf3055270e521b2dff64f2d203ec8040f71958b8588269a82c00c9d7b6a`,
`hostapd-2.6` = `01526b90c1d23bec4b0f052039cc4456c2fd19347b4d830d1d58a0a6aea7117d`),
the ESP-IDF v4.4/v5.2 READMEs, the generated component file lists, the
guard-presence greps and the 2021 reinstall-commit record (regenerate
with `make sources-esp`); `tools/` holds `sae_pwe_stats.py` (seeded
leak measurement), `curve_check.py` (curve point count) and
`esp_evidence.py`. The NuttX kernel sources themselves are **not** committed (see
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
| `upstream/wpa_23.c`, `upstream/wpa_cur.c` (`report/snippets/upstream/`) | hostap `wpa.c` official 2.3 release (w1.fi, sha256 eaaa5bf3…) and current |
| `upstream/sae_2.3.c`, `upstream/sae_2.6_reflection_fixed.c`, `upstream/sae_cur.c` | hostap `sae.c` at 2.3 (pre-Dragonblood), 2.6 + reflection fix (what the KRACK-era 2.6 TPTK trap motivated), and current |
| `Makefile` | builds both harnesses with `-fsanitize=address,undefined` |

### Build and run

```text
# from the module root (m4-cybersecurity-research/):
make snippets   # build + run the NuttX harnesses
make krack      # vulnerable 4-way receiver -> keystream reuse + recovery;
make progress   # (and make sae) the WPA models
make report     # typst compile
cd report/snippets && make run && make fixed   # the NuttX ASan demos
python3 tools/sae_pwe_stats.py    # the hunt-loop leak (module root)
python3 tools/curve_check.py      # point-count of the harness curve
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
technique on `sae_2.3.c` (`sae_derive_pwe_ecc`), which the harnesses do
not compile (it needs the full `crypto_ec_point_*` surface) — it is
kept for reference next to the replica that measures it. Reviewers can
verify byte-for-byte equality against
`https://github.com/apache/nuttx/tree/nuttx-12.7.0` and
`nuttx-12.9.0` / `nuttx-12.10.0`, and against the checked-in
`snippets/upstream/` files. The extract script lives at
`report/snippets/extract_upstream.py`.

### Attempted and not reproduced

The `fs_rename` case (CVE-2025-48769) is documented in Chapter 3 (Case Study 2); the
harness produced ASan use-after-free reports, but only inside a model of
the FAT readdir lifetime we wrote ourselves, which we judged too weak to
publish as a reproduction. The negative result stands.

## Full harness sources

<!--raw-typst #snippet("bt_uart_harness.c", caption: [ "Full host harness for the Bluetooth UART case study."]) -->

<!--raw-typst #snippet("inode_unlink_harness.c", caption: [ "Full host harness for the inode removal case study."]) -->
