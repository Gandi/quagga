#include <zebra.h>

#include "thread.h"
#include "linklist.h"
#include "vty.h"
#include "log.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "if.h"
#include "table.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/dict.h"
#include "isisd/isisd.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_route.h"
#include "isisd/isis_csm.h"
#include "isisd/trill.h"
static int
trill_complete_spf(struct isis_area *area)
{
  int retval;
  dnode_t *dnode;
  struct trill_nickdb_node *tnode;
  /* run spf tree for self*/
  retval = isis_run_select_spf (area, TRILL_LEVEL, AF_TRILL, isis->sysid, NULL);
  if (retval != ISIS_OK)
    zlog_warn ("ISIS-Spf running spf for system returned:%d", retval);

  /*
   * Run SPF for all other RBridges in the campus as well to
   * compute the distribution trees with other RBridges in
   * the campus as root.
   */

  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
    {
	/* nickdb should not contain self information
	 * but in order to be sure we add this check to avoid
	 * recompute self adjencies
	 */
      if(!memcmp(tnode->info.sysid, isis->sysid,ISIS_SYS_ID_LEN))
        continue;
	/* run spf tree for all node in nickdb */
	retval = isis_run_select_spf (area, TRILL_LEVEL, AF_TRILL,
                        tnode->info.sysid ,tnode->rdtree);
      if (retval != ISIS_OK)
        zlog_warn ("ISIS-Spf running spf for:%s returned:%d",
                        print_sys_hostname (tnode->info.sysid), retval);
    }
  /*
   * TODO Process computed SPF trees to create TRILL
   * forwarding and adjacency tables.
   */
  return retval;
}

static int
isis_run_spf_trill (struct thread *thread)
{
  struct isis_area *area;
  int retval;
  area = THREAD_ARG (thread);
  assert (area);
  area->spftree[TRILL_LEVEL - 1]->t_spf = NULL;
  if (!(area->is_type & TRILL_LEVEL))
    {
      return ISIS_WARNING;
    }

  if (isis->debugs & DEBUG_SPF_EVENTS) zlog_debug ("ISIS-Spf (%s) L1 SPF needed, periodic SPF", area->area_tag);
  retval = trill_complete_spf(area);

  THREAD_TIMER_ON (master, area->spftree[TRILL_LEVEL - 1]->t_spf,
			 isis_run_spf_trill, area,
                   isis_jitter (PERIODIC_SPF_INTERVAL, 10));

  return retval;
}

int isis_spf_schedule_trill (struct isis_area *area)
{
  int retval = ISIS_OK;
  struct isis_spftree *spftree = area->spftree[TRILL_LEVEL - 1];
  time_t diff, now = time (NULL);

  if (spftree->pending){
    return retval;
  }

  diff = now - spftree->last_run_timestamp;
  /* FIXME: let's wait a minute before doing the SPF */
  if (now - isis->uptime < 60 || isis->uptime == 0)
    {
      THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_trill, area, 60);
      spftree->pending = 1;
      return retval;
    }
  THREAD_TIMER_OFF (spftree->t_spf);

  if (diff < MINIMUM_SPF_INTERVAL){
      THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_trill, area,
                       MINIMUM_SPF_INTERVAL - diff);
      spftree->pending = 1;
    }
  else{
      spftree->pending = 0;
      retval = trill_complete_spf(area);
      THREAD_TIMER_ON (master, spftree->t_spf, isis_run_spf_trill, area,
                       isis_jitter (PERIODIC_SPF_INTERVAL, 10));
    }

  return retval;
}
