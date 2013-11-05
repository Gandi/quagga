#include <zebra.h>
#include <errno.h>

#include "memory.h"
#include "linklist.h"
#include "isisd/trill.h"
#include "isisd/nickname.h"
#include "isisd/isis_spf.h"

void trill_dict_create_nodes (struct isis_area *area, struct nickinfo *nick)
{
  struct trill_nickdb_node *tnode;

  tnode = XCALLOC (MTYPE_ISIS_TRILL_NICKDB_NODE,
			 sizeof(struct trill_nickdb_node)
			);
  tnode->info = *nick;
  dict_alloc_insert (area->trill->nickdb, &(tnode->info.nick.name), tnode);
  tnode->refcnt = 1;
  dict_alloc_insert (area->trill->sysidtonickdb, tnode->info.sysid, tnode);
  tnode->refcnt++;
  /* Mark the nickname as reserved */
  trill_nickname_reserve(nick->nick.name);
  tnode->rdtree = isis_spftree_new(area);
  /* clear copied nick */
  memset(nick, 0, sizeof (*nick));
}

void trill_dict_remnode ( dict_t *dict, dnode_t *dnode)
{
  struct trill_nickdb_node *tnode;

  assert (dnode);
  tnode = dnode_get (dnode);
  assert(tnode->refcnt);
  tnode->refcnt--;
  if (tnode->refcnt == 0)
    {
      isis_spftree_del (tnode->rdtree);
      trill_nickinfo_del (&tnode->info);
      if (tnode->adjnodes)
        list_delete (tnode->adjnodes);
      XFREE (MTYPE_ISIS_TRILL_NICKDB_NODE, tnode);
    }
  dict_delete_free (dict, dnode);
}

void trill_dict_free (dict_t *dict)
{
  dnode_t *dnode, *next;

  dnode = dict_first (dict);
  while (dnode)
    {
      next = dict_next (dict, dnode);
      trill_dict_remnode (dict, dnode);
      dnode = next;
    }
  dict_free_nodes (dict);
  dict_destroy (dict);
}

/*
 * Delete nickname node in both databases. First a lookup
 * of the node in first db by key1 and using the found node
 * a lookup of the node in second db is done. Asserts the
 * node if exists in one also exist in the second db.
 */
void trill_dict_delete_nodes (dict_t *dict1, dict_t *dict2,
		void *key1, bool key2isnick)
{
  dnode_t *dnode1;
  dnode_t *dnode2;
  struct trill_nickdb_node *tnode;
  int nickname;

  dnode1 = dict_lookup (dict1, key1);
  if (dnode1)
    {
      tnode = (struct trill_nickdb_node *) dnode_get(dnode1);
      if (tnode)
        {
          if (key2isnick)
	    {
              dnode2 = dict_lookup (dict2, &(tnode->info.nick.name));
              nickname = tnode->info.nick.name;
	    }
          else
            {
              dnode2 = dict_lookup (dict2, tnode->info.sysid);
	      nickname = *(int *)key1;
	    }
	  assert (dnode2);
          trill_dict_remnode (dict2, dnode2);

	  /* Mark the nickname as available */
	  trill_nickname_free(nickname);
	}
      trill_dict_remnode (dict1, dnode1);
    }
}
/*
 * Search the nickname database and the sysidtonick database
 * to see if we know a rbridge that matches either the passed nickname
 * or system ID or both.
 */
nickdb_search_result trill_search_rbridge (struct isis_area *area,
							 struct nickinfo *ni,
							 dnode_t **fndnode)
{
  dnode_t *dnode;
  struct trill_nickdb_node *tnode;

  dnode = dict_lookup (area->trill->nickdb, &(ni->nick.name));
  if (dnode == NULL)
	dnode = dict_lookup(area->trill->sysidtonickdb, ni->sysid);
  if (dnode == NULL)
	return NOTFOUND;

  tnode = (struct trill_nickdb_node *) dnode_get(dnode);
  assert (tnode != NULL);
  assert (tnode->refcnt);

  if (fndnode)
    *fndnode = dnode;
  if ( memcmp(&(tnode->info.sysid), ni->sysid, ISIS_SYS_ID_LEN) != 0)
	return FOUND;
  if (tnode->info.nick.name != ni->nick.name)
	return NICK_CHANGED;
  if (tnode->info.nick.priority != ni->nick.priority)
	return PRIORITY_CHANGE_ONLY;
  /* Exact nick and sysid match */
  return DUPLICATE;
}

static void trill_update_nickinfo (struct trill_nickdb_node *tnode,
					     struct nickinfo *recvd_nick)
{
  trill_nickinfo_del(&tnode->info);
  tnode->info = *recvd_nick;
  /* clear copied nick */
  memset(recvd_nick, 0, sizeof (*recvd_nick));
}

/*
 * Update nickname information in the dictionary objects.
 */
void trill_nickdb_update (struct isis_area *area,
					    struct nickinfo *newnick)
{
  dnode_t *dnode;
  struct trill_nickdb_node *tnode;
  nickdb_search_result res;

  res = trill_search_rbridge (area, newnick, &dnode);
  if (res == NOTFOUND)
    {
      trill_dict_create_nodes (area, newnick);
      return;
    }

  assert (dnode);
  tnode = dnode_get (dnode);

  /* If nickname & system ID of the node in our database match
   * the nick received then we don't have to change any dictionary
   * nodes. Update only the node information. Otherwise we update
   * the dictionary nodes.
   */
  if (res == DUPLICATE || res == PRIORITY_CHANGE_ONLY)
    {
      trill_update_nickinfo (tnode, newnick);
      return;
    }

  /*
   * If the RBridge has a new nick then update its nick only.
   */
  if (res == NICK_CHANGED)
    {
      /* Delete the current nick in from our database */
      trill_dict_delete_nodes (area->trill->sysidtonickdb,
	      area->trill->nickdb, tnode->info.sysid, true);
      /* Store the new nick entry */
      trill_dict_create_nodes (area, newnick);
    }
  else
    {
      /*
       * There is another RBridge using the same nick.
       * Determine which of the two RBridges should use the nick.
       * But first we should delete any prev nick associated
       * with system ID sending the newnick as it has just
       * announced a new nick.
       */
      trill_dict_delete_nodes (area->trill->sysidtonickdb,
	      area->trill->nickdb, newnick->sysid, true);

      if (trill_nick_conflict (&(tnode->info), newnick))
        {
          /*
	   * RBridge in tnode should choose another nick.
	   * Delete tnode from our nickdb and store newnick.
	   */
           trill_dict_delete_nodes (area->trill->sysidtonickdb,
	      area->trill->nickdb, tnode->info.sysid, true);
           trill_dict_create_nodes (area, newnick);
        }
    }
}
