### What the code does

The H4 (sometimes "HCI UART") protocol is the framing used between a Bluetooth *host* chip and a Bluetooth *controller* on the same board: a one-byte packet-type indicator, then a small header, then a length declared inside that header. NuttX is the host. `drivers/wireless/bluetooth/bt_uart.c` turns the controller's UART into HCI events and ACL packets for the stack in `wireless/bluetooth/bt_hcicore.c`.

The pre-fix receive loop (`btuart_rxwork`, called on the high-priority work queue for every RX interrupt) is in Figure 1. It reads the 1-byte H4 type, then the per-type header (2 bytes for events, 4 bytes for ACL), then `pktlen` bytes of body — into a fixed-size *stack* array.

<!--raw-typst #snippet("bt_uart_rxwork_pre_fix.c", caption: [ "The pre-fix `btuart_rxwork()` receive path, from nuttx-12.7.0 (drivers/wireless/bluetooth/bt_uart.c): the code shipped from 7.25 until PR #16179."]) -->

Three facts make the window:

1. **The length is attacker-declared.** `pktlen` comes straight off the UART in `hdr->acl.len` (or `hdr->evt.len`). The pre-fix code uses it to choose the destination size without checking it against `CONFIG_BLUETOOTH_UART_RXBUFSIZE` (default 2048, from `drivers/wireless/bluetooth/Kconfig` [@nuttx-bt-kconfig]).
2. **The destination is a stack buffer.** `uint8_t data[CONFIG_BLUETOOTH_UART_RXBUFSIZE]` is a local of `btuart_rxwork`. The overflow therefore smashes the work-queue task's own frame and return addresses, which on a typical Cortex-M target (the market this driver targets) means control-flow corruption, not just data corruption. (In the 12.7.x tree the array was sized by `BLUETOOTH_MAX_FRAMELEN` — see the harness discussion — with the same property.)
3. **There are two buffers, and both are wrong.** Even had the driver checked `pktlen` against its own buffer, the stack then copies the packet into an I/O buffer sized `CONFIG_IOB_BUFSIZE` (default 196 per `mm/iob/Kconfig`, or 1530/1534 on network-heavy defconfigs like the QEMU `netnsh` ones [@nuttx-netnsh]). The advisory and the fix cover both layers: the ACL branch of the driver, and the size check at `bt_receive()` entry.

### Reachability

On a NuttX product, "who can send this frame" has an unusually short answer list: (a) the Bluetooth controller itself — compromised, reprogrammed, or spoofed onto the UART; (b) anyone who can poke the UART physically (the driver has no authentication and the framing is trivially emulated by a $3 dev board glued to the TX line); (c) software already inside the device — which is where it overlaps with fleet attacks, because the same byte stream is what a malicious firmware image to the controller module produces. The important asymmetry: the *host* parses bytes from a component the host trusts less than its own stack, with zero negotiation before parsing begins. No pairing, no encryption, no handshake state: a single frame arriving before any of those exist reaches the vulnerable code.

This is also where the flat-memory philosophy (Section 3) turns a "driver bug" into a "firmware bug": the overflow lands in the only address space the system has.
