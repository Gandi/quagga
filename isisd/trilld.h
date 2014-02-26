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

/* IETF TRILL protocol defined constants */
#define DFLT_NICK_PRIORITY 0x40		/* Default priority for autogen nicks */
#define DFLT_NICK_ROOT_PRIORITY 0x40	/* Default priority for autogen nicks */
#define CONFIGURED_NICK_PRIORITY 0x80	/* MSB of priority set if nick is configured */
#define CONFIGURED_NICK_ROOT_PRIORITY 0x80/* MSB of priority set if nick is configured */
#define MIN_RBRIDGE_PRIORITY 1		/* Min priority of use value */
#define MAX_RBRIDGE_PRIORITY 127	/* Max priority of use value */
#define MIN_RBRIDGE_ROOT_PRIORITY 1	/* Min root priority of use value */
#define MAX_RBRIDGE_ROOT_PRIORITY 65534	/* Max root priority of use value*/
#define MAX_RBRIDGE_NODES (RBRIDGE_NICKNAME_MAX + 1) /* Max RBridges possible */
#define TRILL_NICKNAME_LEN   2		/* 16-bit nickname */
#define TRILL_DFLT_ROOT_PRIORITY 0x40	/* Default tree root priority */

/* trill_info status flags */
#define TRILL_AUTONICK       (1 << 0)  /* nickname auto-generated (else user-provided) */
#define TRILL_LSPDB_ACQUIRED (1 << 1)  /* LSP DB acquired before autogen nick is advertised */
#define TRILL_NICK_SET       (1 << 2)  /* nickname configured (random/user generated) */
#define TRILL_PRIORITY_SET   (1 << 3)  /* nickname priority configured by user */

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
  uint8_t status;		/* status flags */
  dict_t *nickdb;		/* TRILL nickname database */
  dict_t *sysidtonickdb;	/* TRILL sysid-to-nickname database */
  struct list *fwdtbl;		/* RBridge forwarding table */
  struct list *adjnodes;	/* Adjacent nicks for our distrib tree */
  struct list *dt_roots;	/* Our choice of DT roots */
  char * name;			/* bridge name */
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
  /* RBridge distribution tree with this nick as root */
  struct isis_spftree *rdtree;
  /* Our (host RBridge) adjacent nicks on this distrib tree */
  struct list *adjnodes;
} nicknode_t;

/* Constants used in nickname generation/allocation */
#define NICKNAMES_BITARRAY_SIZE (MAX_RBRIDGE_NODES / 8) /* nick usage array */
#define CLEAR_BITARRAY_ENTRYLEN 4         /* stores nicks available per 32 nicks in nick bitarray */
#define CLEAR_BITARRAY_ENTRYLENBITS (4*8)  /* 32 nicks tracked in each entry */
#define CLEAR_BITARRAY_SIZE (MAX_RBRIDGE_NODES / CLEAR_BITARRAY_ENTRYLENBITS)
static u_char clear_bit_count[CLEAR_BITARRAY_SIZE];
/* nickname routines */
static u_char nickbitvector[NICKNAMES_BITARRAY_SIZE];
#define NICK_IS_USED(n)		(nickbitvector[(n)/8] & (1<<((n)%8)))
#define NICK_SET_USED(n)	(nickbitvector[(n)/8] |= (1<<((n)%8)))
#define NICK_CLR_USED(n)	(nickbitvector[(n)/8] &= ~(1<<((n)%8)))


/* trilld.c */
void trill_area_init(struct isis_area *area);
void trill_area_free(struct isis_area *area);
void trill_init();

#endif
