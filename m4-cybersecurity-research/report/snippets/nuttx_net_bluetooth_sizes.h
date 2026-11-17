/* BLUETOOTH_MAX_* sizes copied from include/nuttx/net/bluetooth.h so the
 * harness allocates the same stack buffer as the real 12.7 driver. */
#define BLUETOOTH_L2CAP_HDRLEN 4
#define BLUETOOTH_ACL_HDRLEN   4
#define BLUETOOTH_H4_HDRLEN    1
#define BLUETOOTH_SMP_MTU      65
#define BLUETOOTH_MAX_MTU      70
#define BLUETOOTH_MAX_HDRLEN \
  (BLUETOOTH_L2CAP_HDRLEN + BLUETOOTH_ACL_HDRLEN + BLUETOOTH_H4_HDRLEN)
#define BLUETOOTH_MAX_FRAMELEN  (BLUETOOTH_MAX_MTU + BLUETOOTH_MAX_HDRLEN)

/* CONFIG_BLUETOOTH_UART_RXBUFSIZE: in the fixed build the buffer is the
 * Kconfig-sized one; the fixed build also guards ACL against it. The
 * EVT branch keeps no guard, hence BLUETOOTH_UART_RXBUFSIZE must be the
 * Kconfig default (2048), matching upstream drivers/wireless/bluetooth/
 * Kconfig. The harness defines it before including the extracts. */
