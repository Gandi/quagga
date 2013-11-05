#include <zebra.h>
#include <vty.h>
#include <if.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "memory.h"

#include "isisd/trill.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_events.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_tlv.h"
#include "isisd/isis_csm.h"
#include "isisd/netlink.h"
#include "isisd/nickname.h"
#include "isisd/isis_spf.h"
#include "command.h"
#include "privs.h"

int br_socket_fd = -1;
static struct nl_sock *sock_genl;
int genl_family;
int group_number;

/* thread to read netlink response from kernel */
int receiv_nl(struct thread *thread){
 struct isis_area *area;
 area = THREAD_ARG (thread);
 assert (area);
  nl_recvmsgs_default(sock_genl);
  area->nl_tick = NULL;
  THREAD_READ_ON(master, area->nl_tick, receiv_nl, area,
		     nl_socket_get_fd(sock_genl));
 return ISIS_OK;
}


static int trill_netlink_init(struct isis_area *area){

 sock_genl = nl_socket_alloc();
 genl_connect(sock_genl);
 genl_family = genl_ctrl_resolve(sock_genl, TRILL_NL_FAMILY);
 group_number = genl_ctrl_resolve_grp(sock_genl,
						  TRILL_NL_FAMILY,
						  TRILL_MCAST_NAME);
 nl_socket_disable_seq_check(sock_genl);
 if(!genl_family){
	 zlog_err("unable to find generic netlink family id");
	 abort();
 }
 if ((br_socket_fd = socket(AF_LOCAL, SOCK_STREAM, 0)) < 0)
	 return errno;
 return 0;
}

/* get basic interface information and change it status to up */
static int trill_port_init(const char *b, const char *p, void *arg)
{
   struct isis_area *area = arg;
   struct ifreq ifr;
   struct interface *ifp;
   struct isis_circuit *circ;
   int fd;

   ifp = if_get_by_name (p);
   ifp->ifindex = if_nametoindex(ifp->name);
   /*getting mac @ mtu, flag*/
   fd =  socket(AF_INET, SOCK_DGRAM, 0);
   ifr.ifr_addr.sa_family = AF_INET;
   strncpy(ifr.ifr_name, p, IFNAMSIZ-1);
   ioctl(fd, SIOCGIFHWADDR, &ifr);
   memcpy(ifp->hw_addr, ifr.ifr_hwaddr.sa_data, INTERFACE_HWADDR_MAX);
   ifp->hw_addr_len = ETH_ALEN;
   ioctl(fd, SIOCGIFFLAGS, &ifr);
   ifp->flags = ifr.ifr_flags;
   ioctl(fd, SIOCGIFMTU, &ifr);
   ifp->mtu = ifr.ifr_mtu;
   close(fd);

   if ((circ = ifp->info) ==  NULL){
	circ = isis_csm_state_change (TRILL_ENABLE, circ, area);
	circ = isis_csm_state_change (IF_UP_FROM_Z, circ, ifp);
}

  return 0;
}
int br_foreach_trill_interface(const char *brname, int (*iterator)(const char *br, const char *port, void *arg), void *arg)
{
 int i, count;
 struct dirent **namelist;
 char path[256];

 snprintf(path, 256, "/sys/class/net/" "%s/brif", brname);
 count = scandir(path, &namelist, 0, alphasort);
 for (i = 0; i < count; i++) {
	 /* ignore . and .. directories */
	 if (namelist[i]->d_name[0] == '.' && (namelist[i]->d_name[1] == '\0' ||
		 (namelist[i]->d_name[1] == '.' && namelist[i]->d_name[2] ==  '\0')))
		 continue;
	 int fd;
	 struct ifreq ifr;
	 u_char hw_addr[INTERFACE_HWADDR_MAX];
	 fd =  socket(AF_INET, SOCK_DGRAM, 0);
	 ifr.ifr_addr.sa_family = AF_INET;
	 strncpy(ifr.ifr_name, namelist[i]->d_name, IFNAMSIZ-1);
	 ioctl(fd, SIOCGIFHWADDR, &ifr);
	 close(fd);
	 memcpy(hw_addr, ifr.ifr_hwaddr.sa_data, INTERFACE_HWADDR_MAX);
	 /* filter non trill interface via mac addresses */
	 if (!strcmp(snpa_print(hw_addr), NON_TRILL_MAC)){
		 continue;
	}
      if (iterator(brname, namelist[i]->d_name, arg))
		break;
 }
 for (i = 0; i < count; i++)
	 free(namelist[i]);
 free(namelist);
 return count;
}

static char trill_port_load(struct isis_area *area)
{
 struct interface *ifp;
 struct listnode *node, *nnode;
 struct isis_circuit *circ;
 int err;

 for (ALL_LIST_ELEMENTS_RO (iflist, node, ifp)){
   ifp->flags &= ~IFF_UP;
 }

 err = br_foreach_trill_interface(area->trill->name, trill_port_init, area);
 if (!err)
   return false;
 for (ALL_LIST_ELEMENTS(iflist, node, nnode, ifp)){
   if (!(ifp->flags & IFF_UP) && (circ = ifp->info) !=  NULL){
     isis_csm_state_change (TRILL_DISABLE, circ, area);
     isis_csm_state_change (IF_DOWN_FROM_Z, circ, area);
   }
 }
 return true;
}

void trill_struct_init(struct isis_area *area)
{
  struct trill_info *trill= area->trill;
  if(trill)
  {
	trill->status = 0;
	trill->nick.priority = DEFAULT_PRIORITY;
	trill->nick.name = 0xFFFF;
	trill->root_priority = DEFAULT_PRIORITY;
	trill->nickdb = dict_create(MAX_RBRIDGE_NODES, nick_cmp);
	trill->sysidtonickdb = dict_create(MAX_RBRIDGE_NODES, sysid_cmp);
	trill->spf_completed = false;
	trill->dt_roots = list_new();
	nickname_init();
	memset (area->trill->lspdb_acq_reqs, 0, sizeof(trill->lspdb_acq_reqs));
  }
}

static void set_area_nickname(struct isis_area *area,uint16_t nickname)
{
  struct listnode *ifnode;
  struct interface *ifp;
  ifnode = listhead (iflist);
  if (ifnode != NULL)
    {
      ifp = listgetdata (ifnode);
      struct nl_msg *msg;
      struct trill_nl_header *trnlhdr;
      msg = nlmsg_alloc();
      trnlhdr=genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, genl_family, sizeof(struct trill_nl_header), NLM_F_REQUEST,
			  TRILL_CMD_SET_RBRIDGE, TRILL_NL_VERSION);
      if(!trnlhdr)
	abort();
      nla_put_u16(msg, TRILL_ATTR_U16, nickname);
      trnlhdr->ifindex=ifp->ifindex;
      trnlhdr->total_length= sizeof(msg);
      trnlhdr->msg_number=1;
      nl_send_auto_complete(sock_genl, msg);
      nlmsg_free(msg);
    }
}

void trill_nickname_gen(struct isis_area *area)
{
  u_int16_t nick;
  nick = trill_nickname_alloc();
  if (nick == RBRIDGE_NICKNAME_NONE)
  {
    zlog_err("RBridge nickname allocation failed.  No nicknames available.");
    abort();
  }
  else
  {
    area->trill->nick.name = htons(nick);
    set_area_nickname(area,nick);
    if (isis->debugs & DEBUG_TRILL_EVENTS)
      zlog_debug("ISIS TRILL generated nick:%u", nick);
  }
}

/*
 * Called from isisd to handle trill nickname command.
 * Nickname is user configured and in host byte order
 */
bool trill_area_nickname(struct isis_area *area, u_int16_t nickname)
{
  int savednick;

  if (nickname == RBRIDGE_NICKNAME_NONE)
    {
      /* Called from "no trill nickname" command */
      trill_nickname_gen (area);
      SET_FLAG (area->trill->status, TRILL_NICK_SET);
      SET_FLAG (area->trill->status, TRILL_AUTONICK);
      lsp_regenerate_schedule (area,TRILL_LEVEL,1);
      return true;
    }

  nickname = htons(nickname);
  savednick = area->trill->nick.name;
  area->trill->nick.name = nickname;

  set_area_nickname(area,ntohs(area->trill->nick.name));
  area->trill->nick.priority |= CONFIGURED_NICK_PRIORITY;
  /*
   * Check if we know of another RBridge already using this nickname.
   * If yes check if it conflicts with the nickname in the database.
   */
  if (is_nickname_used(nickname))
    {
      struct nickinfo ni;
      dnode_t *dnode;
      struct trill_nickdb_node *tnode;

      ni.nick = area->trill->nick;
      memcpy(ni.sysid, isis->sysid, ISIS_SYS_ID_LEN);
      if (trill_search_rbridge (area, &ni, &dnode) == FOUND)
        {
          assert (dnode);
          tnode = dnode_get (dnode);
          if (trill_nick_conflict (&(tnode->info), &ni))
            {
              trill_dict_delete_nodes (area->trill->nickdb,
		     area->trill->sysidtonickdb, &nickname, false);
	    }
	  else
	    {
              /*
	       * The other nick in our nickdb has greater priority so return
	       * fail, restore nick and let user configure another nick.
	       */
               area->trill->nick.name = savednick;
	       set_area_nickname(area,ntohs(area->trill->nick.name));
	       area->trill->nick.priority &= ~CONFIGURED_NICK_PRIORITY;
               return false;
	    }
	}
    }

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
  if (priority)
    {
      area->trill->nick.priority = priority;
      SET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
    }
  else
    {
      /* Called from "no trill nickname priority" command */
      area->trill->nick.priority = DFLT_NICK_PRIORITY;
      UNSET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
    }

  /*
   * Set the configured nickname priority bit if the
   * nickname was not automatically generated.
   */
  if (!CHECK_FLAG(area->trill->status, TRILL_AUTONICK))
     area->trill->nick.priority |= CONFIGURED_NICK_PRIORITY;
  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit)){
    circuit->priority[TRILL_LEVEL - 1] = priority;
  }
}

static void trill_nickname_root_priority_update(struct isis_area *area,
								u_int16_t priority)
{
  if (priority)
    {
      area->trill->root_priority = priority;
      SET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
    }
  else
    {
      /* Called from "no trill nickname priority" command */
      area->trill->root_priority = DFLT_NICK_ROOT_PRIORITY;
      UNSET_FLAG(area->trill->status, TRILL_PRIORITY_SET);
    }
  /*
   * Set the configured nickname priority bit if the
   * nickname was not automatically generated.
   */
  if (!CHECK_FLAG(area->trill->status, TRILL_AUTONICK))
     area->trill->root_priority |= CONFIGURED_NICK_PRIORITY;
}

void trill_lspdb_acquire_event(struct isis_circuit *circuit,
					 lspdbacq_state caller)
{
  struct isis_area *area;
  u_int8_t cid;
  struct listnode *cnode;
  int done = true;
  area = circuit->area;
  cid = circuit->circuit_id;
  if (!isis->trill_active)
    return;
 if (CHECK_FLAG (area->trill->status, (TRILL_LSPDB_ACQUIRED | TRILL_NICK_SET)))
    return;

  switch(caller)
    {
    case CSNPRCV:
    case CSNPSND:
      LSPDB_ACQTRYINC (area, cid);
      break;
    case PSNPSNDTRY:
      if (circuit->circ_type != CIRCUIT_T_BROADCAST)
        LSPDB_ACQTRYINC (area, cid);
      break;
    default:
      break;
    }
  for (ALL_LIST_ELEMENTS_RO (area->circuit_list, cnode, circuit))
    {
      cid = circuit->circuit_id;

      /*
       * If on any circuit we have reached max tries
       * we consider LSP DB acquisition as done and
       * assign ourselves a nickname
       */
      if (LSPDB_ACQTRYVAL (area, cid) > MAX_LSPDB_ACQTRIES)
        {
          done = true;
         break;
        }

      /*
       * If on any circuits we haven't received min LSPDB update
       * packets then we wait until we hit max tries above
       * on any circuit. If not it can only mean there is no other
       * IS-IS instance on any of our circuits and so we wait.
       */
      if (LSPDB_ACQTRYVAL (area, cid) < MIN_LSPDB_ACQTRIES)
        done = false;
    }
  if (done)
    {
      /*
       * LSP DB acquired state, sufficient to start
       * advertising our nickname. Set flags, pick a
       * new nick if necessary and trigger new LSPs with the nick.
       */
      SET_FLAG (area->trill->status, TRILL_LSPDB_ACQUIRED);
      if (ntohs(area->trill->nick.name) == RBRIDGE_NICKNAME_NONE)
       {
         trill_nickname_gen (area);
         SET_FLAG (area->trill->status, TRILL_NICK_SET);
         SET_FLAG (area->trill->status, TRILL_AUTONICK);
         lsp_regenerate_schedule (area,TRILL_LEVEL,1);
       }
    }
}

static void trill_destroy_nickfwdtable(void *obj)
{
  XFREE (MTYPE_ISIS_TRILL_FWDTBL_NODE, obj);
}
void trill_create_nickfwdtable(struct isis_area *area)
{
  struct listnode *node;
  struct isis_vertex *vertex;
  struct isis_adjacency *adj;
  struct list *fwdlist = NULL;
  struct list *oldfwdlist;
  struct nickfwdtable_node *fwdnode;
  struct isis_spftree *rdtree;
  oldfwdlist = area->trill->fwdtbl;
  int firstnode = true;
  /* forwarding table is based on spftree rooted at local node */
  rdtree = area->spftree[TRILL_LEVEL - 1];

  for (ALL_LIST_ELEMENTS_RO (rdtree->paths, node, vertex))
  {
    if (firstnode)
    {
	/* first node in path list is local node */
	fwdlist = list_new();
	fwdlist->del = trill_destroy_nickfwdtable;
	firstnode = false;
	continue;
    }
    if (vertex->type != VTYPE_NONPSEUDO_IS &&
	vertex->type != VTYPE_NONPSEUDO_TE_IS)
    {
	continue;
    }
    /* Adj_N: {Adj(N)} next hop or neighbor list */
    if (listhead (vertex->Adj_N) &&
	(adj = listgetdata (listhead (vertex->Adj_N))))
    {
	fwdnode = XCALLOC (MTYPE_ISIS_TRILL_FWDTBL_NODE,
				 sizeof(struct nickfwdtable_node));
	fwdnode->dest_nick = sysid_to_nick (area, vertex->N.id);
	memcpy(fwdnode->adj_snpa, adj->snpa, sizeof(fwdnode->adj_snpa));
	fwdnode->interface = adj->circuit->interface;
	listnode_add (fwdlist, fwdnode);
    }
    else
    {
	zlog_warn("nickfwdtable: node %s is unreachable",
		    print_sys_hostname (vertex->N.id));
	/* if a node is unreachable delete it from nickdb */
	trill_dict_delete_nodes (area->trill->sysidtonickdb,
					 area->trill->nickdb,
					 vertex->N.id,
					 true);
    }
  }

  area->trill->fwdtbl = fwdlist;
  if (oldfwdlist != NULL)
    list_delete (oldfwdlist);
}

static struct nickfwdtable_node * trill_fwdtbl_lookup (struct isis_area *area,
									 u_int16_t nick)
{
  struct listnode *node;
  struct nickfwdtable_node *fwdnode;
  if (area->trill->fwdtbl == NULL){
    zlog_warn("trill_fwdtbl_lookup:fwdtbl is null");
    return NULL;
  }

  for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode)){
    if (fwdnode->dest_nick == nick)
	return fwdnode;
    }
  return NULL;
}

static void trill_add_nickadjlist(struct isis_area *area, struct list *adjlist,
					    struct isis_vertex *vertex)
{
  u_int16_t nick;

  nick = sysid_to_nick (area, vertex->N.id);
  if (!nick){
    return;
  }
  /* add only nodes that can be reached from local one (exist in forwarding
   * table)*/
  if (!trill_fwdtbl_lookup(area, nick))
    return;
  /* each node has to be added once */
  if (listnode_lookup (adjlist, (void *)(u_long)nick) != NULL)
    return;
  listnode_add (adjlist, (void *)(u_long)nick);
}

void trill_create_nickadjlist(struct isis_area *area,
						 struct trill_nickdb_node *nicknode)
{
  struct listnode *node;
  struct listnode *cnode;
  struct isis_vertex *vertex;
  struct isis_vertex *pvertex;
  struct isis_vertex *cvertex;
  struct isis_vertex *rbvertex = NULL;
  struct list *adjlist;
  struct list *oldadjlist;
  struct list *pseudoparents;
  struct list *pseudochildren;
  struct isis_spftree *rdtree;

  /* if nicknode is NULL then local adjacency node are computed */
  if (nicknode == NULL)
   {
     rdtree = area->spftree[TRILL_LEVEL - 1];
     oldadjlist = area->trill->adjnodes;
   }
  else
   {
     rdtree = nicknode->rdtree;
     oldadjlist = nicknode->adjnodes;
   }

  /* Find our node in the distribution tree first */
  for (ALL_LIST_ELEMENTS_RO (rdtree->paths, node, vertex))
    {
      if (vertex->type != VTYPE_NONPSEUDO_IS &&
	  vertex->type != VTYPE_NONPSEUDO_TE_IS)
	continue;
      if (memcmp (vertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN) == 0)
        {
          rbvertex = vertex;
	  break;
	}
    }

  /* Determine adjacencies by looking up the parent & child nodes */
  if (rbvertex)
    {
      adjlist = list_new();

      if (listcount (vertex->parents) > 0)
      {
         /*
          * Find adjacent parent node: check parent is not another vertex
          * with our system ID and the parent node is on SPF paths
          */
         pvertex =(struct isis_vertex*)listgetdata(listhead(rbvertex->parents));
         while (pvertex != NULL)
           {
              if (memcmp (pvertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN)
                  && (listnode_lookup (rdtree->paths, pvertex)))
               break;
             if(pvertex->parents != NULL){
               if (listhead(pvertex->parents) !=NULL){
                 pvertex = (struct isis_vertex *)
                 listgetdata(listhead(pvertex->parents));
               }
               else
                 goto pvertex_NULL;
             }
             else
             {
pvertex_NULL:
               pvertex=NULL;
               break;
             }
           }
         /* Add only non pseudo parents to adjacency list
          * if parent is a pseudo node add the first of his non pseudo
          * parents
          */
         for (ALL_LIST_ELEMENTS_RO (rbvertex->parents, node, pvertex)){
            if (pvertex->type !=  VTYPE_PSEUDO_TE_IS )
                trill_add_nickadjlist (area, adjlist, pvertex);
            else
                trill_add_nickadjlist (area, adjlist,
                                       listgetdata(listhead(pvertex->parents)));
         }
      }

      if (rbvertex->children && listhead (rbvertex->children)){
          pseudochildren = list_new();
           for (ALL_LIST_ELEMENTS_RO (rbvertex->children, node, vertex))
            {
             if (memcmp (vertex->N.id, area->isis->sysid, ISIS_SYS_ID_LEN) == 0)
                        listnode_add(pseudochildren, vertex);
              else if (listnode_lookup (rdtree->paths, vertex))
                        trill_add_nickadjlist (area, adjlist, vertex);
            }
          /*
           * If we find child vertices above with our system ID(pseudo node)then
           * we search their descendants and any that are found are added as
           *  our adjacencies
           */
          for (node = listhead(pseudochildren); node != NULL;
               node = listnextnode(node))
             {
                if ((vertex = listgetdata(node)) == NULL)
                break;
               for (ALL_LIST_ELEMENTS_RO (vertex->children, cnode, cvertex))
                {
                   if ((memcmp (cvertex->N.id,
                        area->isis->sysid,ISIS_SYS_ID_LEN) == 0)
                       && listnode_lookup(pseudochildren, cvertex) == NULL)
                     listnode_add(pseudochildren, cvertex);

                        if (listnode_lookup(rdtree->paths, cvertex)){
                     trill_add_nickadjlist (area, adjlist, cvertex);
                       }
                }
            }
            if(pseudochildren)
                list_delete(pseudochildren);
      }

      if (nicknode != NULL)
		nicknode->adjnodes = adjlist;
      else
		area->trill->adjnodes = adjlist;
	if(oldadjlist)
	  list_delete (oldadjlist);
    }
}

void trill_init(int argc, char **argv)
{
 const char *instname;
 const char *instarea;
 struct isis_area *area;
 struct listnode *ifnode;
 struct interface *ifp;
 struct area_addr *addr;

 int count;
 struct dirent **namelist;
 DIR *dir;
 char path[SYSFS_PATH_MAX];
 zlog_set_level(NULL, ZLOG_DEST_SYSLOG, LOG_WARNING);
 /* check given parameters number */

 if (optind !=  argc -2 ){
 zlog_err("instance name and area name are required for TRILL");
 exit(1);
 }

 instname = argv[optind];
 instarea = argv[optind+1];
 isis->trill_active = true;
  /* TRILL is different from the standard IS-IS; it uses one area address */
 isis->max_area_addrs = 1;

 area = isis_area_create (instarea);
 (void) strlcpy (area->trill->name, instname, MAXLINKNAMELEN);

 /* start check bridge state */
 snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s", area->trill->name);
 dir = opendir(path);
 if (dir == NULL) {
 zlog_err("device %s does not exist", area->trill->name);
 exit(1);
 }
 closedir(dir);
 snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/bridge",
	    area->trill->name);
 dir = opendir(path);
 if (dir == NULL) {
 zlog_err("device %s is not a valid bridge \n", area->trill->name);
 if (zlog_default)
	closezlog (zlog_default);
 exit(1);
 }
 closedir(dir);
 snprintf(path, SYSFS_PATH_MAX, SYSFS_CLASS_NET "%s/brif", area->trill->name);
 count = scandir(path, &namelist, 0, alphasort);
 if (count < 0){
 zlog_err("bridge %s have no attached interface\n", area->trill->name);
 if (zlog_default)
	closezlog (zlog_default);
 exit(1);
 }
 /* end of bridge state check */

 /* Set up to use new (extended) metrics only */
 area->newmetric = 1;
 area->oldmetric = 0;

 /* get interface configuration and change their status to up */
 if (!trill_port_load (area)) {
	 printf("trill port load failed \n");
	 exit(1);
 }

 /* init netlink socket in order to communicate with data plan */
 trill_netlink_init(area);
 if (nl_socket_set_nonblocking(sock_genl))
 zlog_warn("cannot set non blocking socket\n");
 ifnode = listhead (iflist);
 if (ifnode !=  NULL){
	 struct nl_msg *msg;
	 struct trill_nl_header *trnlhdr;

	 msg = nlmsg_alloc();
	 /* try to get Rbridge nickname from data plan
	  * this is usefull when daemon crash and distant Rbridge
	  * still have valid topology information concerving nickname
	  * transmitted from data plan will avoid uneccesary topology recompute
	  * in distant RBridges
	  */
	 trnlhdr = genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ,
				genl_family,
				sizeof(struct trill_nl_header),
				NLM_F_REQUEST,
				TRILL_CMD_GET_RBRIDGE,
				TRILL_NL_VERSION);
	 if(!trnlhdr)
		 abort();
	 nla_put_u16(msg, TRILL_ATTR_U16, RBRIDGE_NICKNAME_NONE);
	 /* interface index is needed to identify bridge */
	 ifp = listgetdata (ifnode);
	 trnlhdr->ifindex = ifp->ifindex;
	 trnlhdr->total_length = sizeof(msg);
	 /*first netlink message to be sent */
	 trnlhdr->msg_number = 1;

	 if(nl_socket_add_membership(sock_genl, group_number))
		 zlog_warn("unable to join multicast group\n");

	/* replace default callback by the one defined in isisd/netlink.c */
	 if(nl_socket_modify_cb(sock_genl, NL_CB_MSG_IN, NL_CB_CUSTOM,
		 parse_cb, (void *)area))
		 zlog_warn("unable to modify callback\n");

	 /* Send message over netlink socket */
	nl_send_auto_complete(sock_genl, msg);
	nlmsg_free(msg);

      THREAD_READ_ON(master, area->nl_tick, receiv_nl, area,
			   nl_socket_get_fd(sock_genl));

	/* generate rare address and sysid */
	addr = XMALLOC (MTYPE_ISIS_AREA_ADDR, sizeof (struct area_addr));
	addr->addr_len = 8;
	addr->area_addr[0] = 0;
	addr->area_addr[7] = 0;
	memcpy((addr->area_addr)+1, ifp->hw_addr, ETH_ALEN);
	memcpy (isis->sysid, GETSYSID (addr), ISIS_SYS_ID_LEN);
	isis->sysid_set = 1;
	// Forget the systemID part of the address
	addr->addr_len -=  (ISIS_SYS_ID_LEN + 1);
	listnode_add (area->area_addrs, addr);
 }
 isis_event_system_type_change (area, TRILL_LEVEL);
 lsp_regenerate_schedule (area, TRILL_LEVEL, 1);
}

void trill_exit(void)
{
 nl_close(sock_genl);
 close(br_socket_fd);
}

void trill_nickdb_print (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  struct trill_nickdb_node *tnode;
  const char *sysid;

  vty_out(vty, "    System ID          Hostname     Nickname   Priority  %s",
	    VTY_NEWLINE);

  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
    {
      sysid = sysid_print (tnode->info.sysid);
      vty_out (vty, "%-21s %-10s  %8d  %8d%s",
		   sysid, print_sys_hostname (tnode->info.sysid),
		   ntohs (tnode->info.nick.name), tnode->info.nick.priority,
		   VTY_NEWLINE);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
    if(area->trill->dt_roots)
           if (listhead(area->trill->dt_roots))
                   vty_out (vty,"    TREE_ROOT:       %8d    %s",
                          ntohs (listgetdata(listhead(area->trill->dt_roots))),
                              VTY_NEWLINE);

}

static void trill_fwdtbl_print (struct vty *vty, struct isis_area *area)
{
  struct listnode *node;
  struct nickfwdtable_node *fwdnode;

  vty_out(vty, "RBridge        nickname   interface  nexthop MAC%s",
	    VTY_NEWLINE);
  if (area->trill->fwdtbl == NULL)
    return;
  for (ALL_LIST_ELEMENTS_RO (area->trill->fwdtbl, node, fwdnode))
    {
      vty_out (vty, "%-15s   %-5d      %-5s  %-15s%s",
		   print_sys_hostname (nick_to_sysid (area, fwdnode->dest_nick)),
		   ntohs (fwdnode->dest_nick), fwdnode->interface->name,
		   snpa_print (fwdnode->adj_snpa), VTY_NEWLINE);
    }
}

void
trill_circuits_print_all (struct vty *vty, struct isis_area *area)
{
  struct listnode *node;
  struct isis_circuit *circuit;
  if (area->circuit_list == NULL)
    return;

  for (ALL_LIST_ELEMENTS_RO(area->circuit_list, node, circuit))
    {
     vty_out (vty, "%sInterface %s:%s",
		  VTY_NEWLINE,
		  circuit->interface->name,
		  VTY_NEWLINE);
    }
}

static void trill_adjtbl_print (struct vty *vty, struct isis_area *area,
					  struct trill_nickdb_node *nicknode)
{
  struct listnode *node;
  struct nickfwdtable_node *fwdnode;
  void *listdata;
  u_int16_t nick;
  int idx = 0;
  struct list *adjnodes;

  if (nicknode == NULL)
       adjnodes = area->trill->adjnodes;
  else
       adjnodes = nicknode->adjnodes;

  if (adjnodes == NULL)
    return;

  for (ALL_LIST_ELEMENTS_RO (adjnodes, node, listdata))
    {
      nick = (u_int16_t)(u_long)listdata;
      fwdnode = trill_fwdtbl_lookup (area, nick);
      if (!fwdnode)
        continue;
      vty_out (vty, "%-15s   %-5d      %-5s  %-15s%s",
               print_sys_hostname (nick_to_sysid(area, nick)),
	       ntohs (nick), fwdnode->interface->name,
	       snpa_print (fwdnode->adj_snpa), VTY_NEWLINE);
    }
  vty_out (vty, "%s", VTY_NEWLINE);
}

static void trill_adjtbl_print_all (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  struct trill_nickdb_node *tnode;

  vty_out(vty, "Adjacencies on our RBridge distribution tree:%s", VTY_NEWLINE);
  trill_adjtbl_print (vty, area, NULL);

  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
    {
      vty_out(vty, "Adjacencies on distribution tree rooted at RBridge %s :%s",
	      print_sys_hostname (tnode->info.sysid), VTY_NEWLINE);
       if(tnode)
               trill_adjtbl_print (vty, area, tnode);
    }
}

static void
trill_print_paths (struct vty *vty, struct isis_area *area)
{
  dnode_t *dnode;
  struct trill_nickdb_node *tnode;

  for (ALL_DICT_NODES_RO(area->trill->nickdb, dnode, tnode))
  {
    if (tnode->rdtree && tnode->rdtree->paths->count > 0)
    {
      vty_out (vty, "%sRBridge distribution paths for RBridge:%s%s",
               VTY_NEWLINE, print_sys_hostname (tnode->info.sysid),
               VTY_NEWLINE);
      isis_print_paths (vty, tnode->rdtree->paths, tnode->info.sysid);
     }
  }
 }


DEFUN (show_trill_nickdatabase,
       show_trill_nickdatabase_cmd,
       "show trill nickname database",
       SHOW_STR TRILL_STR "TRILL IS-IS nickname information\n"
       "IS-IS TRILL nickname database\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (!isis->trill_active || (isis->area_list->count == 0))
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "Area %s nickname:%d priority:%d %s",
          area->area_tag ? area->area_tag : "null",
          ntohs(area->trill->nick.name),
		   area->trill->nick.priority,
		   VTY_NEWLINE);

	vty_out (vty, "%s", VTY_NEWLINE);
	vty_out (vty, "IS-IS TRILL nickname database:%s", VTY_NEWLINE);
	trill_nickdb_print (vty, area);
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

  if (!isis->trill_active || (isis->area_list->count == 0))
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "IS-IS TRILL forwarding table:%s", VTY_NEWLINE);
      trill_fwdtbl_print (vty, area);
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

  if (!isis->trill_active || (isis->area_list->count == 0))
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

DEFUN (show_trill_adjtable,
       show_trill_adjtable_cmd,
       "show trill adjacencies",
       SHOW_STR TRILL_STR
       "IS-IS TRILL adjacency lists\n")
{
  struct listnode *node;
  struct isis_area *area;

  if (!isis->trill_active || (isis->area_list->count == 0))
    return CMD_SUCCESS;

  assert (isis->area_list->count == 1);

  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {
      vty_out (vty, "IS-IS TRILL adjacencies in all distribution trees:%s%s",
		   VTY_NEWLINE, VTY_NEWLINE);
      trill_adjtbl_print_all (vty, area);
    }
  vty_out (vty, "%s%s", VTY_NEWLINE, VTY_NEWLINE);
  return CMD_SUCCESS;
}

/*
 * Enable TRILL support in IS-IS command, only one IS-IS area allowed.
 */
DEFUN (isis_trill,
	 isis_trill_cmd,
	 "isis trill",
	 "Enable use of IS-IS as routing protocol for TRILL\n"
	)
{
  if (!isis->trill_active && isis->area_list->count > 0)
    {
      vty_out (vty, "Cannot enable TRILL. IS-IS area already configured%s", VTY_NEWLINE);
      return CMD_WARNING;
    }
  isis->trill_active = true;
  return CMD_SUCCESS;
}

/*
 * Disable TRILL support in IS-IS command
 */
DEFUN (no_isis_trill,
	 no_isis_trill_cmd,
	 "no isis trill",
	 "Disable use of IS-IS as routing protocol for TRILL\n")
{
  isis->trill_active = false;
  return CMD_SUCCESS;
}

DEFUN (trill_nickname,
	 trill_nickname_cmd,
	 "trill nickname WORD",
       TRILL_STR
       TRILL_NICK_STR
       "<1-65534>\n")
{
  struct isis_area *area;
  u_int16_t nickname;

  area = vty->index;
  assert (area);
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  VTY_GET_INTEGER_RANGE ("TRILL nickname", nickname, argv[0],
		  RBRIDGE_NICKNAME_MIN + 1, RBRIDGE_NICKNAME_MAX);
  if (!trill_area_nickname (area, nickname))
    {
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
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

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
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  VTY_GET_INTEGER_RANGE ("TRILL nickname priority", priority, argv[0],
		  MIN_RBRIDGE_PRIORITY, MAX_RBRIDGE_PRIORITY);
  trill_nickname_priority_update (area, priority);
  trill_nickname_root_priority_update (area, priority);
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
  assert (area->isis);
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  trill_nickname_priority_update (area, 0);
  trill_nickname_root_priority_update (area, 0);
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
  if (!area->isis->trill_active)
    {
      vty_out (vty, "TRILL is not enabled%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  (void) strlcpy(area->trill->name, argv[0], MAXLINKNAMELEN);
  return CMD_SUCCESS;
}

DEFUN (show_trill_topology,
       show_trill_topology_cmd,
       "show trill topology",
       SHOW_STR
       "TRILL information\n"
       "TRILL paths to Intermediate Systems\n")
{
  struct listnode *node;
  struct isis_area *area;
  if (!isis->area_list || isis->area_list->count == 0)
    return CMD_SUCCESS;
  for (ALL_LIST_ELEMENTS_RO (isis->area_list, node, area))
    {

      vty_out (vty, "Area %s:%s", area->area_tag ? area->area_tag : "null",
                  VTY_NEWLINE);

         if (area->spftree[TRILL_LEVEL - 1]
             && area->spftree[TRILL_LEVEL - 1]->paths->count > 0)
           {
             vty_out (vty, "TRILL path %s",
                          VTY_NEWLINE);
             isis_print_paths (vty, area->spftree[TRILL_LEVEL - 1]->paths,
                                       isis->sysid);
             vty_out (vty, "%s", VTY_NEWLINE);
           }
       vty_out (vty,
                  "TRILL paths for others RBridges",
                        VTY_NEWLINE);
        trill_print_paths (vty, area);
      vty_out (vty, "%s", VTY_NEWLINE);
    }
  return CMD_SUCCESS;
}


void install_trill_elements (void)
{
  install_element (VIEW_NODE, &show_trill_nickdatabase_cmd);
  install_element (VIEW_NODE, &show_trill_fwdtable_cmd);
  install_element (VIEW_NODE, &show_trill_adjtable_cmd);
  install_element (VIEW_NODE, &show_trill_circuits_cmd);
  install_element (VIEW_NODE, &show_trill_topology_cmd);

  install_element (ENABLE_NODE, &show_trill_nickdatabase_cmd);
  install_element (ENABLE_NODE, &show_trill_fwdtable_cmd);
  install_element (ENABLE_NODE, &show_trill_adjtable_cmd);
  install_element (ENABLE_NODE, &show_trill_circuits_cmd);
  install_element (ENABLE_NODE, &show_trill_topology_cmd);

  install_element (CONFIG_NODE, &isis_trill_cmd);
  install_element (CONFIG_NODE, &no_isis_trill_cmd);

  install_element (ISIS_NODE, &trill_nickname_cmd);
  install_element (ISIS_NODE, &no_trill_nickname_cmd);

  install_element (ISIS_NODE, &trill_nickname_priority_cmd);
  install_element (ISIS_NODE, &no_trill_nickname_priority_cmd);
  install_element (ISIS_NODE, &trill_instance_cmd);

}
