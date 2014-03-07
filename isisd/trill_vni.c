/*
 * IS-IS Rout(e)ing protocol - trilld_vni.c
 *
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * modified by gandi.net
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#include <zebra.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "log.h"
#include "memory.h"
#include "hash.h"
#include "vty.h"
#include "linklist.h"
#include "thread.h"
#include "if.h"
#include "stream.h"
#include "command.h"
#include "privs.h"


#include "isisd/dict.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/trilld.h"
#include "isisd/isisd.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_adjacency.h"

int generate_supported_vni(struct isis_area *area)
{
  int old_count, changed;
  struct listnode *node;
  struct list * old_list;
  void *vni;
  changed = false;
  struct trill *trill = area->trill;
  old_count = listcount(trill->supported_vni);
  old_list = trill->supported_vni;
  trill->supported_vni = list_new();

  /* Step one check portential change on configured vni list */
  for (ALL_LIST_ELEMENTS_RO (trill->configured_vni, node, vni)) {
      if (!listnode_lookup (old_list, vni)) {
	changed = true;
      }
    listnode_add(trill->supported_vni,(void *) (uint32_t)(u_long) vni);
  }
  list_delete (old_list);

  /* Step two is use less if circuit list has a unique interface */
  if ( listcount(area->circuit_list) < 2 )
    goto out;

  /*
   * Step two check if a vni is received from two diffrents interfaces
   *  in such case add it to supported vni list
   */

out :
  /*
   * if vni count has changed or one vni was changed
   * return true in order to force a LSP send
   */
  return ( (listcount(trill->supported_vni) != old_count) || changed );
}
