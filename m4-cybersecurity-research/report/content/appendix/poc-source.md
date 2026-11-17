The complete harness sources are listed below, byte-identical to
`report/snippets/`. The `.inc` extracts are omitted for length: they are
verbatim slices of the upstream files named in their headers, easiest to
review in the repository against `snippets/upstream/` and the NuttX
tags.

<!--raw-typst #snippet("bt_uart_harness.c", caption: [ "Bluetooth UART receive-path harness (both builds share this file)."]) -->

<!--raw-typst #snippet("krack_harness.c", caption: [ "KRACK supplicant-receiver model (vulnerable and fixed builds)."]) -->

<!--raw-typst #snippet("sae_harness.c", caption: [ "SAE reflection-DoS model (vulnerable and guarded builds)."]) -->

<!--raw-typst #snippet("inode_unlink_harness.c", caption: [ "Inode removal harness (Chapter 3, Case Study 2)."]) -->
