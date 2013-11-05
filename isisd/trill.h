#ifndef ISIS_TRILL_H
#define ISIS_TRILL_H
#include <net/ethernet.h>

#include "isisd/dict.h"
#include "isisd/isis_common.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_flags.h"

#include "isisd/isisd.h"


#define MAXLINKNAMELEN	32

/* trill_info status flags */

/* nickname auto-generated (else user-provided) */
#define TRILL_AUTONICK       (1 << 0)
/* LSP DB acquired before autogen nick is advertised */
#define TRILL_LSPDB_ACQUIRED (1 << 1)
/* nickname configured (random/user generated) */
#define TRILL_NICK_SET       (1 << 2)
/* nickname priority configured by user */
#define TRILL_PRIORITY_SET   (1 << 3)

struct trill_nickname
{
  u_int16_t name;               /* network byte order */
  u_int8_t priority;
};

struct trill_info
{
  struct trill_nickname nick;   /* local nick */
  int status;                   /* status flags */
  bool spf_completed;		  /* spf flags */
  dict_t *nickdb;               /* nickname database */
  dict_t *sysidtonickdb;        /* sysid-to-nickname database */
  /* counter used in LSP database acquisition (per circuit) */
  u_int8_t lspdb_acq_reqs [ISIS_MAX_CIRCUITS_COUNT];
  struct list *fwdtbl;          /* RBridge forwarding table */
  struct list *adjnodes;        /* Adjacent nicks for our distrib. tree */
  struct list *dt_roots;        /* Our choice of DT roots */
  u_int16_t root_priority;      /* Root tree priority */
  char name[MAXLINKNAMELEN];    /* instance name */
};

/* TRILL nickname information (node-specific) */
struct nickinfo
{
  struct trill_nickname nick;       /* Nick of the node  */
  u_char sysid[ISIS_SYS_ID_LEN];    /* NET/sysid of node */
  u_int8_t flags;                   /* TRILL flags advertised by node */
  struct list *dt_roots;            /* Distrib. Trees chosen by node */
  u_int16_t root_priority;          /* Root tree priority */
  u_int16_t root_count;             /* Root tree count */
};

/* Nickname database node */
struct trill_nickdb_node
{
  struct nickinfo info;         /* Nick info of the Rbridge X*/
  struct isis_spftree *rdtree;  /* topology tree rooted at  X */
  struct list *adjnodes;        /* local nick ajacent RBridge on tree
					rooted @ X */
  u_int32_t refcnt;
};

/* RBridge forwarding table node */
struct nickfwdtable_node
{
  u_int16_t dest_nick;               /* destination RBridge nick */
  u_char adj_snpa[ETH_ALEN];         /* MAC address of the adj node */
  struct interface *interface;       /* local interface to reach this dest */
};

/* RBridge search function return status codes */
typedef enum
{
  NOTFOUND = 1,
  FOUND,
  DUPLICATE,
  NICK_CHANGED,
  PRIORITY_CHANGE_ONLY
} nickdb_search_result;

/* LSP database acquisition process states */
typedef enum
{
  CSNPRCV = 0,
  CSNPSND,
  PSNPSNDTRY,
} lspdbacq_state;

void trill_init(int argc, char **argv);
void trill_struct_init(struct isis_area *);
void trill_exit(void);
void install_trill_elements (void);

/* trill_nodedb.c */
extern void trill_nickdb_update (struct isis_area *area,
					    struct nickinfo *newnick);
extern void trill_dict_create_nodes(struct isis_area *, struct nickinfo *);
extern void trill_dict_remnode(dict_t *, dnode_t *);
extern void trill_dict_free(dict_t *);
extern void trill_dict_delete_nodes(dict_t *, dict_t *,void *, bool);
extern nickdb_search_result trill_search_rbridge (struct isis_area *,
								  struct nickinfo *,
								  dnode_t **);
/* trill_bpdu.c */
extern int send_trill_hello (struct isis_circuit *);
extern int send_trill_hello_thread (struct thread *);
extern int process_trill_hello (struct isis_circuit *, u_char *);
#endif
