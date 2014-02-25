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

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */
#ifndef _ZEBRA_ISIS_TRILL_H
#define _ZEBRA_ISIS_TRILL_H

/* Nickname range */
#define RBRIDGE_NICKNAME_MIN		0x0000
#define RBRIDGE_NICKNAME_MAX		0xFFFF
/* Define well-known nicknames */
#define RBRIDGE_NICKNAME_NONE		RBRIDGE_NICKNAME_MIN
#define RBRIDGE_NICKNAME_MINRES		0xFFC0
#define RBRIDGE_NICKNAME_MAXRES		(RBRIDGE_NICKNAME_MAX - 1)
#define RBRIDGE_NICKNAME_UNUSED		RBRIDGE_NICKNAME_MAX

#define MIN_RBRIDGE_RANDOM_NICKNAME	(RBRIDGE_NICKNAME_NONE + 1)
#define MAX_RBRIDGE_RANDOM_NICKNAME	(RBRIDGE_NICKNAME_MINRES - 1)

/* trill nickname structure */
struct trill_nickname
{
  uint16_t name;
  uint8_t priority;
  uint8_t pad;
};

/* trill structure */
struct trill
{
  struct trill_nickname nick;	/* our nick */
  dict_t *nickdb;		/* TRILL nickname database */
  dict_t *sysidtonickdb;	/* TRILL sysid-to-nickname database */
  struct list *fwdtbl;		/* RBridge forwarding table */
  struct list *adjnodes;	/* Adjacent nicks for our distrib tree */
  struct list *dt_roots;	/* Our choice of DT roots */
  uint16_t root_priority;	/* Root tree priority */
  uint16_t  tree_root;
};

/* TRILL nickname information (node-specific) */
typedef struct nickinfo
{
  struct trill_nickname nick;	/* Nick of the node  */
  u_char sysid[ISIS_SYS_ID_LEN];/* NET/sysid of node */
  uint8_t flags;		/* TRILL flags advertised by node */
  struct list *dt_roots;	/* Distrib. Trees chosen by node */
  uint16_t root_priority;	/* Root tree priority */
  uint16_t root_count;		/* Root tree count */
} nickinfo_t;

/* Nickname database node */
typedef struct trill_nickdb_node
{
  nickinfo_t info;	/* Nick info of the node */
  /* RBridge distribution tree with this nick as root */*
  struct isis_spftree *rdtree;
  /* Our (host RBridge) adjacent nicks on this distrib tree */*
  struct list *adjnodes;
} nicknode_t;
#endif
