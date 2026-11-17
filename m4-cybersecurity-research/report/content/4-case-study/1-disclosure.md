### The disclosure

CVE-2025-35003 was assigned to two missing bounds checks in the NuttX Bluetooth UART receive path, published to oss-security on 26 May 2025 [@oss-sec-35003]. NVD rates it CVSS 3.1 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) — network, low complexity, no privileges, full impact [@cve-2025-35003]. The description names "maliciously crafted packets" on the HCI/UART interface and lists the consequence set as crash, denial of service, or arbitrary code execution. The affected range is 7.25 before 12.9.0: the driver was broken for roughly the whole period the project maintained a Bluetooth stack. The security page lists the finders as Chongqing Lei and Zhen Ling (Southeast University), with Lei also writing the remediation; the CVE coordinators were Arnout Engelen and NuttX committer Tomek Cedro [@nuttx-security]. The fix shipped in the next release after disclosure, as the standard cycle prescribes.

The fix is small and reviewable. PR apache/nuttx#16179 adds two length guards [@pr-16179]:

```c
/* drivers/wireless/bluetooth/bt_uart.c  (part of the fix) */
         else if (data[0] == H4_ACL)
           {
             pktlen = hdr->acl.len;
+
+            if (pktlen + H4_HEADER_SIZE + hdrlen >
+                CONFIG_BLUETOOTH_UART_RXBUFSIZE)
+              {
+                wlwarn("WARNING: H4 packet is too long\n");
+                break;
+              }
+
             type = BT_ACL_IN;
           }
```

and in the stack's entry point:

```c
/* wireless/bluetooth/bt_hcicore.c  (part of the fix) */
 int bt_receive(FAR struct bt_driver_s *btdev, enum bt_buf_type_e type,
                FAR void *data, size_t len)
 {
+  if (len + BLUETOOTH_H4_HDRLEN > CONFIG_IOB_BUFSIZE)
+    {
+      wlerr("ERROR: Data too long\n");
+      return -EINVAL;
+    }
```

Two notes before the anatomy. First, the CVSS 9.8 with AV:N is arguable and we will defend it: "network" in CVSS for this driver means the HCI transport, which on nearly every NuttX product is a UART to a co-located controller module, not the air interface. Second, the fix PR also repaired a missing error path in `bt_hci_cmd_send_sync()` (the sync-semaphore teardown on a failed wait), and the CVE description itself pairs it with "Stack-based Buffer Overflow" [NVD]: the HCI layer had its own unchecked copy, which is why two guards were needed.
