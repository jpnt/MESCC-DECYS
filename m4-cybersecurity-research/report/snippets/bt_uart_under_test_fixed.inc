static ssize_t btuart_read(FAR struct btuart_upperhalf_s *upper,
                           FAR uint8_t *buffer, size_t buflen,
                           size_t minread)
{
  FAR const struct btuart_lowerhalf_s *lower;
  ssize_t ntotal = 0;
  ssize_t nread;

  wlinfo("buflen %zu minread %zu\n", buflen, minread);

  DEBUGASSERT(upper != NULL && upper->lower != NULL);
  lower = upper->lower;
  DEBUGASSERT(lower->read != NULL);

  while (buflen > 0)
    {
      nread = lower->read(lower, buffer, buflen);
      if (nread == 0 || nread == -EINTR)
        {
          wlwarn("Got zero bytes from UART\n");
          if (ntotal < minread)
            {
              continue;
            }

          break;
        }
      else if (nread < 0)
        {
          wlwarn("Returned error %zd\n", nread);
          return nread;
        }

      wlinfo("read %zd remaining %zu\n", nread, buflen - nread);

      buflen -= nread;
      ntotal += nread;
      buffer += nread;
    }

  return ntotal;
}

static void btuart_rxwork(FAR void *arg)
{
  FAR struct btuart_upperhalf_s *upper;
  uint8_t data[CONFIG_BLUETOOTH_UART_RXBUFSIZE];
  enum bt_buf_type_e type;
  unsigned int hdrlen;
  unsigned int pktlen;
  ssize_t nread;
  union
    {
      struct bt_hci_evt_hdr_s evt;
      struct bt_hci_acl_hdr_s acl;
    }

  *hdr;

  upper = (FAR struct btuart_upperhalf_s *)arg;

  /* Beginning of a new packet.
   * Read the first byte to get the packet type.
   */

  while (true)
    {
      nread = btuart_read(upper, data, H4_HEADER_SIZE, 0);
      if (nread != H4_HEADER_SIZE)
        {
          wlwarn("WARNING: Unable to read H4 packet type: %zd\n", nread);
          break;
        }

      if (data[0] == H4_EVT)
        {
          hdrlen = sizeof(struct bt_hci_evt_hdr_s);
        }
      else if (data[0] == H4_ACL)
        {
          hdrlen = sizeof(struct bt_hci_acl_hdr_s);
        }
      else
        {
          wlerr("ERROR: Unknown H4 type %u\n", data[0]);
          break;
        }

      nread = btuart_read(upper, data + H4_HEADER_SIZE,
                          hdrlen, hdrlen);
      if (nread != hdrlen)
        {
          wlwarn("WARNING: Unable to read H4 packet header: %zd\n", nread);
          break;
        }

      hdr = (FAR void *)(data + H4_HEADER_SIZE);

      if (data[0] == H4_EVT)
        {
          pktlen = hdr->evt.len;
          type = BT_EVT;
        }
      else if (data[0] == H4_ACL)
        {
          pktlen = hdr->acl.len;

          if (pktlen + H4_HEADER_SIZE + hdrlen >
              CONFIG_BLUETOOTH_UART_RXBUFSIZE)
            {
              wlwarn("WARNING: H4 packet is too long\n");
              break;
            }

          type = BT_ACL_IN;
        }
      else
        {
          wlerr("ERROR: Unknown H4 type %u\n", data[0]);
          break;
        }

      nread = btuart_read(upper, data + H4_HEADER_SIZE + hdrlen,
                          pktlen, pktlen);
      if (nread != pktlen)
        {
          wlwarn("WARNING: Unable to read H4 packet: %zd\n", nread);
          break;
        }

      /* Pass buffer to the stack */

      BT_DUMP("Received", data, H4_HEADER_SIZE + hdrlen + pktlen);
      bt_netdev_receive(&upper->dev, type, data + H4_HEADER_SIZE,
                        hdrlen + pktlen);
    }
}

