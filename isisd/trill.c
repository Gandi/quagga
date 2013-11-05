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
	   circ = isis_csm_state_change (IF_UP_FROM_Z, NULL, ifp);
	   circ = isis_csm_state_change (TRILL_ENABLE, circ, area);
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
 isis->trill_active = true;
 /* TRILL is different from the standard IS-IS; it uses one area address */
 isis->max_area_addrs = 1;

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
}

void trill_exit(void)
{
 nl_close(sock_genl);
 close(br_socket_fd);
}
