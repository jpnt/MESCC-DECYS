static void btuart_rxwork(FAR void *arg)
{
  FAR struct btuart_upperhalf_s *upper;
  uint8_t data[BLUETOOTH_MAX_FRAMELEN];
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

  nread = btuart_read(upper, data, H4_HEADER_SIZE, 0);
  if (nread != H4_HEADER_SIZE)
    {
      wlwarn("WARNING: Unable to read H4 packet type: %zd\n", nread);
      goto errout_with_busy;
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
      goto errout_with_busy;
    }

  nread = btuart_read(upper, data + H4_HEADER_SIZE,
                      hdrlen, hdrlen);
  if (nread != hdrlen)
    {
      wlwarn("WARNING: Unable to read H4 packet header: %zd\n", nread);
      goto errout_with_busy;
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
      type = BT_ACL_IN;
    }
  else
    {
      wlerr("ERROR: Unknown H4 type %u\n", data[0]);
      goto errout_with_busy;
    }

  nread = btuart_read(upper, data + H4_HEADER_SIZE + hdrlen,
                      pktlen, pktlen);
  if (nread != pktlen)
    {
      wlwarn("WARNING: Unable to read H4 packet: %zd\n", nread);
      goto errout_with_busy;
    }

  /* Pass buffer to the stack */

  BT_DUMP("Received", data, H4_HEADER_SIZE + hdrlen + pktlen);
  upper->busy = false;
  bt_netdev_receive(&upper->dev, type, data + H4_HEADER_SIZE,
                    hdrlen + pktlen);
  return;

errout_with_busy:
  upper->busy = false;
}
