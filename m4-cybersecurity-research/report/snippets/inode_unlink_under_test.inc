static FAR struct inode *inode_unlink(FAR const char *path)
{
  struct inode_search_s desc;
  FAR struct inode *inode = NULL;
  int ret;

  /* Verify parameters.  Ignore null paths */

  if (path == NULL)
    {
      return NULL;
    }

  /* Find the node to unlink */

  SETUP_SEARCH(&desc, path, true);

  ret = inode_search(&desc);
  if (ret >= 0)
    {
      inode = desc.node;
      DEBUGASSERT(inode != NULL);

      /* If peer is non-null, then remove the node from the right of
       * of that peer node.
       */

      if (desc.peer != NULL)
        {
          desc.peer->i_peer = inode->i_peer;
        }

      /* Then remove the node from head of the list of children. */

      else
        {
          DEBUGASSERT(desc.parent != NULL);
          desc.parent->i_child = inode->i_peer;
        }

      inode->i_peer   = NULL;
      inode->i_parent = NULL;
      atomic_fetch_sub(&inode->i_crefs, 1);
    }

  RELEASE_SEARCH(&desc);
  return inode;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

