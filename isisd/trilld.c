/*
 * IS-IS Rout(e)ing protocol - isis_trill.h
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


#include "isisd/dict.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/trilld.h"
#include "isisd/isisd.h"


int nickavailcnt = RBRIDGE_NICKNAME_MINRES - RBRIDGE_NICKNAME_NONE - 1;

int nickname_init()
{
  u_int i;
  memset(nickbitvector, 0, sizeof(nickbitvector));
  for (i = 0; i < sizeof (clear_bit_count); i++)
    clear_bit_count[i] = CLEAR_BITARRAY_ENTRYLENBITS;
  /* These two are always reserved */
  NICK_SET_USED(RBRIDGE_NICKNAME_NONE);
  NICK_SET_USED(RBRIDGE_NICKNAME_UNUSED);
  clear_bit_count[RBRIDGE_NICKNAME_NONE / CLEAR_BITARRAY_ENTRYLENBITS]--;
  clear_bit_count[RBRIDGE_NICKNAME_UNUSED / CLEAR_BITARRAY_ENTRYLENBITS]--;
}

static int trill_nickname_nickbitmap_op(u_int16_t nick, int update, int val)
{
  if (nick == RBRIDGE_NICKNAME_NONE || nick == RBRIDGE_NICKNAME_UNUSED)
    return false;
  if (val) {
    if (NICK_IS_USED(nick))
      return true;
    if (!update)
      return false;
    NICK_SET_USED(nick);
    if (nick < RBRIDGE_NICKNAME_MINRES)
      nickavailcnt--;
    clear_bit_count[nick / CLEAR_BITARRAY_ENTRYLENBITS]--;
  } else {
    if (!NICK_IS_USED(nick))
      return true;
    if (!update)
      return false;
    NICK_CLR_USED(nick);
    if (nick < RBRIDGE_NICKNAME_MINRES)
      nickavailcnt++;
    clear_bit_count[nick / CLEAR_BITARRAY_ENTRYLENBITS]++;
  }
  return false;
}
static int is_nickname_used(u_int16_t nick_nbo)
{
  return trill_nickname_nickbitmap_op(ntohs(nick_nbo), false, true);
}
static void trill_nickname_reserve(u_int16_t nick_nbo)
{
  trill_nickname_nickbitmap_op(ntohs(nick_nbo), true, true);
}

static void trill_nickname_free(u_int16_t nick_nbo)
{
  trill_nickname_nickbitmap_op(ntohs(nick_nbo), true, false);
}
static uint16_t trill_nickname_alloc(void)
{
  uint i, j, k;
  uint16_t nick;
  uint16_t nicknum;
  uint16_t freenickcnt = 0;
  if (nickavailcnt < 1)
    return RBRIDGE_NICKNAME_NONE;
  /*
   * Note that rand() usually returns 15 bits, so we overlap two values to make
   * sure we're getting at least 16 bits (as long as rand() returns 8 bits or
   * more).  Using random() instead would be better, but isis_main.c uses
   * srand.
   */
  nicknum = ((rand() << 8) | rand()) % nickavailcnt;
  for ( i = 0; i < sizeof (clear_bit_count); i++ ) {
    freenickcnt += clear_bit_count[i];
    if (freenickcnt <= nicknum)
      continue;
    nicknum -= freenickcnt - clear_bit_count[i];
    nick = i * CLEAR_BITARRAY_ENTRYLEN * 8;
    for ( j = 0; j < CLEAR_BITARRAY_ENTRYLEN; j++) {
      for (k = 0; k < 8; k++, nick++) {
	if (!NICK_IS_USED(nick) && nicknum-- == 0) {
	  trill_nickname_nickbitmap_op (nick, true, true);
	  return nick;
	}
      }
    }
    break;
  }
  return 0;
}

static void gen_nickname(struct isis_area *area)
{
  uint16_t nick;
  nick = trill_nickname_alloc();
  if (nick == RBRIDGE_NICKNAME_NONE) {
    zlog_err("RBridge nickname allocation failed.  No nicknames available.");
    abort();
  } else {
    area->trill->nick.name = htons(nick);
    if (isis->debugs & DEBUG_TRILL_EVENTS)
      zlog_debug("ISIS TRILL generated nick:%u", nick);
  }
}

/*
 * Called from isisd to handle trill nickname command.
 * Nickname is user configured and in host byte order
 */
int trill_area_nickname(struct isis_area *area, u_int16_t nickname)
{
  uint16_t savednick;

  if (nickname == RBRIDGE_NICKNAME_NONE) {
    /* Called from "no trill nickname" command */
    gen_nickname (area);
    SET_FLAG (area->trill->status, TRILL_NICK_SET);
    SET_FLAG (area->trill->status, TRILL_AUTONICK);
    return true;
  }

  nickname = htons(nickname);
  savednick = area->trill->nick.name;
  area->trill->nick.name = nickname;
  area->trill->nick.priority |= CONFIGURED_NICK_PRIORITY;

  trill_nickname_reserve(nickname);
  SET_FLAG(area->trill->status, TRILL_NICK_SET);
  UNSET_FLAG(area->trill->status, TRILL_AUTONICK);
  return true;
}

static void trill_nickname_priority_update(struct isis_area *area,
					   u_int8_t priority)
{
  struct isis_circuit *circuit;
  struct listnode *cnode;
  if (priority) {
    area->trill->nick.priority = priority;
    area->trill->root_priority = priority;
    SET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
  }
  else {
    /* Called from "no trill nickname priority" command */
    area->trill->nick.priority = DFLT_NICK_PRIORITY;
    area->trill->root_priority = TRILL_DFLT_ROOT_PRIORITY;
    UNSET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
  }

  /*
   * Set the configured nickname priority bit if the
   * nickname was not automatically generated.
   */
  if (!CHECK_FLAG(area->trill->status, TRILL_AUTONICK)) {
    area->trill->nick.priority |= CONFIGURED_NICK_PRIORITY;
  }
  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit)) {
    circuit->priority[TRILL_ISIS_LEVEL - 1] = priority;
  }
}

static int nick_cmp(const void *key1, const void *key2)
{
  return (memcmp(key1, key2, sizeof(u_int16_t)));
}

static int sysid_cmp(const void *key1, const void *key2)
{
  return (memcmp(key1, key2, ISIS_SYS_ID_LEN));
}

void trill_area_init(struct isis_area *area)
{
  struct trill* trill;
  area->trill = XCALLOC (MTYPE_ISIS_TRILLAREA, sizeof (struct trill));
  trill = area->trill;
  trill->nick.priority = DEFAULT_PRIORITY;
  trill->nick.name = RBRIDGE_NICKNAME_NONE;

  trill->nickdb = dict_create(MAX_RBRIDGE_NODES, nick_cmp);
  trill->sysidtonickdb = dict_create(MAX_RBRIDGE_NODES, sysid_cmp);
  trill->fwdtbl = list_new();
  trill->adjnodes = list_new();
  trill->dt_roots = list_new();
  trill->root_priority = DEFAULT_PRIORITY;
  trill->tree_root= RBRIDGE_NICKNAME_NONE;

  /* FIXME For the moment force all TRILL area to be level 1 */
  area->is_type = IS_LEVEL_1;
}

void trill_area_free(struct isis_area *area)
{
  if(area->trill->nickdb) {
    dict_free(area->trill->nickdb);
    dict_destroy (area->trill->nickdb);
  }
  if(area->trill->sysidtonickdb) {
    dict_free(area->trill->sysidtonickdb);
    dict_destroy (area->trill->sysidtonickdb);
  }
  if (area->trill->fwdtbl)
    list_delete (area->trill->fwdtbl);
  if (area->trill->adjnodes)
    list_delete (area->trill->adjnodes);
  if (area->trill->dt_roots)
    list_delete (area->trill->dt_roots);
  XFREE (MTYPE_ISIS_TRILLAREA, area->trill);
}

void trill_nickdb_print (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  const char *sysid;

  u_char *lsysid;
  u_int16_t lpriority;

  vty_out(vty, "    System ID          Hostname     Nickname   Priority  %s",
	  VTY_NEWLINE);
  lpriority = area->trill->nick.priority;
  lsysid = area->isis->sysid;


  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode)) {
    sysid = sysid_print (tnode->info.sysid);
    vty_out (vty, "%-21s %-10s  %8d  %8d%s", sysid,
	     print_sys_hostname (tnode->info.sysid),
	     ntohs (tnode->info.nick.name),
	     tnode->info.nick.priority,VTY_NEWLINE);
  }
  if(area->trill->tree_root)
    vty_out (vty,"    TREE_ROOT:       %8d    %s",
	     ntohs (area->trill->tree_root),VTY_NEWLINE);
}

void
trill_circuits_print_all (struct vty *vty, struct isis_area *area)
{
  struct listnode *node;
  struct isis_circuit *circuit;

  if (area->circuit_list == NULL)
    return;

  for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
    vty_out (vty, "%sInterface %s:%s", VTY_NEWLINE,
	     circuit->interface->name, VTY_NEWLINE);
}

static nicknode_t * trill_nicknode_lookup(struct isis_area *area, uint16_t nick)
{
  dnode_t *dnode;
  nicknode_t *tnode;
  dnode = dict_lookup (area->trill->nickdb, &nick);
  if (dnode == NULL)
    return (NULL);
  tnode = (nicknode_t *) dnode_get (dnode);
  return (tnode);
}

/* Lookup system ID when given a nickname */
static u_char * nick_to_sysid(struct isis_area *area, u_int16_t nick)
{
  nicknode_t *tnode;

  tnode = trill_nicknode_lookup(area, nick);
  if (tnode == NULL)
    return (NULL);
  return tnode->info.sysid;
}
static void trill_fwdtbl_print (struct vty *vty, struct isis_area *area)
{
  struct listnode *node;
  nickfwdtblnode_t *fwdnode;

  if (area->trill->fwdtbl == NULL)
    return;

  vty_out(vty, "RBridge        nickname   interface  nexthop MAC%s", VTY_NEWLINE);
  for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode)) {
    vty_out (vty, "%-15s   %-5d      %-5s  %-15s%s",
	     print_sys_hostname (nick_to_sysid (area, fwdnode->dest_nick)),
	     ntohs (fwdnode->dest_nick), fwdnode->interface->name,
	     snpa_print (fwdnode->adj_snpa), VTY_NEWLINE);
  }
}

DEFUN (trill_nickname,
       trill_nickname_cmd,
       "trill nickname WORD",
       TRILL_STR
       TRILL_NICK_STR
       "<1-65534>\n")
{
  struct isis_area *area;
  uint16_t nickname;
  area = vty->index;
  assert (area);
  assert (area->trill);
  VTY_GET_INTEGER_RANGE ("TRILL nickname", nickname, argv[0],
			 RBRIDGE_NICKNAME_MIN + 1, RBRIDGE_NICKNAME_MAX);
  if (!trill_area_nickname (area, nickname)) {
    vty_out (vty, "TRILL nickname conflicts with another RBridge nickname,"
    " must select another.%s", VTY_NEWLINE);
    return CMD_WARNING;
  }
  return CMD_SUCCESS;
}

DEFUN (no_trill_nickname,
       no_trill_nickname_cmd,
       "no trill nickname",
       TRILL_STR
       TRILL_NICK_STR)
{
  struct isis_area *area;
  area = vty->index;
  assert (area);
  assert (area->trill);
  trill_area_nickname (area, 0);
  return CMD_SUCCESS;
}

DEFUN (trill_nickname_priority,
       trill_nickname_priority_cmd,
       "trill nickname priority WORD",
       TRILL_STR
       TRILL_NICK_STR
       "priority of use field\n"
       "<1-127>\n")
{
  struct isis_area *area;
  u_int8_t priority;
  area = vty->index;
  assert (area);
  assert (area->trill);
  VTY_GET_INTEGER_RANGE ("TRILL nickname priority", priority, argv[0],
			 MIN_RBRIDGE_PRIORITY, MAX_RBRIDGE_PRIORITY);
  trill_nickname_priority_update (area, priority);
  return CMD_SUCCESS;
}
DEFUN (no_trill_nickname_priority,
       no_trill_nickname_priority_cmd,
       "no trill nickname priority WORD",
       TRILL_STR
       TRILL_NICK_STR
       "priority of use field\n")
{
  struct isis_area *area;
  area = vty->index;
  assert (area);
  assert (area->trill);
  trill_nickname_priority_update (area, 0);
  return CMD_SUCCESS;
}
DEFUN (trill_instance, trill_instance_cmd,
       "trill instance WORD",
       TRILL_STR
       "TRILL instance\n"
       "instance name\n")
{
  struct isis_area *area;

  area = vty->index;
  assert (area);
  assert (area->isis);
  area->trill->name = strdup(argv[0]);
  return CMD_SUCCESS;
}

DEFUN (show_trill_nickdatabase,
       show_trill_nickdatabase_cmd,
       "show trill nickname database",
       SHOW_STR TRILL_STR "TRILL IS-IS nickname information\n"
       "IS-IS TRILL nickname database\n")
{

  struct listnode *node;
  struct isis_area *area;
  dnode_t *dnode;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area)) {
    vty_out (vty, "Area %s nickname:%d priority:%d %s",
	     area->area_tag ? area->area_tag : "null",
	     ntohs(area->trill->nick.name),
	     area->trill->nick.priority,VTY_NEWLINE);

    vty_out (vty, "%s", VTY_NEWLINE);
    vty_out (vty, "IS-IS TRILL nickname database:%s", VTY_NEWLINE);
    trill_nickdb_print (vty, area);
  }
  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}
DEFUN (show_trill_circuits,
       show_trill_circuits_cmd,
       "show trill circuits",
       SHOW_STR TRILL_STR
       "IS-IS TRILL circuits\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "IS-IS TRILL circuits:%s%s",
		      VTY_NEWLINE, VTY_NEWLINE);
      trill_circuits_print_all (vty, area);
    }
  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}
DEFUN (show_trill_fwdtable,
       show_trill_fwdtable_cmd,
       "show trill forwarding",
       SHOW_STR TRILL_STR
       "IS-IS TRILL forwarding table\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (isis->area_list->count == 0)
    return CMD_SUCCESS;
  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area)) {
    vty_out (vty, "IS-IS TRILL forwarding table:%s", VTY_NEWLINE);
    trill_fwdtbl_print (vty, area);
  }
  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}

void trill_init()
{
  install_element (ISIS_NODE, &trill_nickname_cmd);
  install_element (ISIS_NODE, &no_trill_nickname_cmd);
  install_element (ISIS_NODE, &trill_nickname_priority_cmd);
  install_element (ISIS_NODE, &no_trill_nickname_priority_cmd);
  install_element (ISIS_NODE, &trill_instance_cmd);

  install_element (VIEW_NODE, &show_trill_nickdatabase_cmd);
  install_element (VIEW_NODE, &show_trill_circuits_cmd);
  install_element (VIEW_NODE, &show_trill_fwdtable_cmd);

  install_element (ENABLE_NODE, &show_trill_nickdatabase_cmd);
  install_element (ENABLE_NODE, &show_trill_circuits_cmd);
  install_element (ENABLE_NODE, &show_trill_fwdtable_cmd);


}