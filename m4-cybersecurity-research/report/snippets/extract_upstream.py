"""Generate the NuttX .inc extracts (run once; outputs checked in)."""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2] / "work"
SRC = {
    "bt_uart_under_test.inc":
        (ROOT / "bt_uart_nuttx-12.7.0.c",
         'static ssize_t btuart_read', 'static void btuart_rxcallback'),
    "bt_uart_under_test_fixed.inc":
        (ROOT / "nuttx/drivers/wireless/bluetooth/bt_uart.c",
         'static ssize_t btuart_read', 'static void btuart_rxcallback'),
    "inode_unlink_under_test.inc":
        (ROOT / "nuttx/fs/inode/fs_inoderemove.c",
         'static FAR struct inode *inode_unlink(',
         '/****************************************************************************\n * Name: inode_remove'),
}
guard = 'pktlen + H4_HEADER_SIZE'
dst = pathlib.Path(__file__).resolve().parent
for name, (path, a, b) in SRC.items():
    if not path.exists():
        sys.exit(f"missing {path}; run `make sources` first")
    t = path.read_text()
    i, j = t.index(a), t.index(b)
    s = t[i:j]
    if name == "bt_uart_under_test.inc":
        assert guard not in s, "expected pre-fix 12.7 extract"
    elif name == "bt_uart_under_test_fixed.inc":
        assert guard in s, "expected the fixed ACL guard in 12.9.0"
    (dst / name).write_text(s)
print("wrote extracts")
