/*
 * inode_unlink_harness.c
 *
 * Host reproduction of CVE-2025-48768, "Release of Invalid Pointer or
 * Reference" in inode_unlink() in fs/inode/fs_inoderemove.c. Affects
 * NuttX 10.0.0 through 12.9.x; fixed in 12.10.0 by PR apache/nuttx#16437,
 * which replaces the debug-only assumption with a real error return:
 *
 *      if (desc.parent == NULL)
 *        {
 *          inode = NULL;
 *          goto errout;
 *        }
 *
 * The function under test, inode_unlink(), is the verbatim 12.9.0
 * source (inode_unlink_under_test.inc, extracted the same way as the
 * bt_uart harness). inode_search() and the inode struct are replaced
 * by a small model that matches the kernel's semantics: searching "/"
 * finds the root with desc.parent == NULL and desc.peer == NULL -- the
 * state the pre-fix code does not handle.
 *
 * Why this is a denial of service and not just an assert: in release
 * builds (CONFIG_DEBUG_ASSERTS is off by default) the pre-fix code
 * runs `desc.parent->i_child = inode->i_peer` with desc.parent ==
 * NULL. On an MMU target that is a NULL write trapped as a crash; the
 * advisory rates it a DoS. On flat (no-MMU) builds the write lands at
 * address 0 + offsetof(i_child) -- into the vector/interrupt area --
 * which is why the same bug is worse than it looks on small parts.
 *
 * Attack surface (from the advisory): "Users of filesystem based
 * services with write access that were exposed over the network
 * (i.e. FTP)". The FTP DELE/RMD handlers reach inode_remove().
 *
 * Build:  make inode_unlink_harness
 * Run:    ./inode_unlink_harness
 *
 * The demonstration builds with AddressSanitizer so the NULL write is
 * reported instead of silently corrupting: ASan traps the store
 * through the NULL parent pointer exactly where the pre-fix code
 * performs it.
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define FAR
#ifndef OK
#  define OK 0
#endif
#define DEBUGASSERT(x) ((void)(x))   /* CONFIG_DEBUG_ASSERTS is off by default */
#define atomic_fetch_sub(p, n) (*(p) -= (n))
#define atomic_read(p) (*(p))
typedef volatile int atomic_t;
static void fs_heap_free(void *p) { free(p); }

/* --- inode model -------------------------------------------------------- */

struct inode {              /* field order matches include/nuttx/fs/fs.h */
  FAR struct inode *i_parent;   /* link to parent level inode  */
  FAR struct inode *i_peer;     /* link to same level inode    */
  FAR struct inode *i_child;    /* link to lower level inode   */
  atomic_t          i_crefs;    /* references to inode         */
};

static struct inode *g_root;

struct inode_search_s {
  FAR const char *path;
  FAR struct inode *node;
  FAR struct inode *peer;
  FAR struct inode *parent;
};

#define SETUP_SEARCH(desc, p, nf) \
  do { (desc)->path = (p); (desc)->node = NULL; (desc)->peer = NULL; \
       (desc)->parent = NULL; } while (0)
#define RELEASE_SEARCH(desc) ((void)0)

/* Kernel-shaped search: for "/" the root is returned with no parent and
 * no peer. */
static int inode_search(FAR struct inode_search_s *desc)
{
  FAR const char *name = desc->path;

  while (*name == '/') name++;
  if (*name == '\0')
    {
      desc->node = g_root;
      desc->parent = NULL;      /* root: the trigger for the bug */
      desc->peer = NULL;
      return 0;
    }
  return -ENOENT;
}

/* --- the pre-fix code under test (verbatim 12.9.0) ---------------------- */

#include "inode_unlink_under_test.inc"

/* --- inode_remove()/inode_free(), kernel shape --------------------------- */

static void inode_free(FAR struct inode *inode)
{
  if (inode != NULL)
    {
      inode_free(inode->i_peer);
      inode_free(inode->i_child);
      fs_heap_free(inode);
    }
}

int inode_remove(FAR const char *path)
{
  FAR struct inode *inode;

  inode = inode_unlink(path);
  if (inode)
    {
      if (atomic_read(&inode->i_crefs))
        {
          return -EBUSY;
        }
      else
        {
          DEBUGASSERT(inode->i_peer == NULL);
          inode_free(inode);
          return OK;
        }
    }

  return -ENOENT;
}

/* --- test ---------------------------------------------------------------- */

int main(void)
{
  g_root = malloc(sizeof *g_root);
  memset(g_root, 0, sizeof *g_root);
  g_root->i_crefs = 0;          /* nobody holds the root: removal proceeds */

  printf("[ftp] attacker session: DELE \"/\" on a filesystem service\n");
  printf("      exposed over the network -> remove(\"/\") -> inode_remove\n");
  printf("[kernel] inode_remove(\"/\") on the 12.9.0 pre-fix code...\n");
  fflush(stdout);

  int ret = inode_remove("/");
  printf("[kernel] inode_remove returned %d (unreachable on a crash)\n", ret);
  return ret == 0 ? 0 : 1;
}
