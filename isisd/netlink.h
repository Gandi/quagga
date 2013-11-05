#ifndef _ZEBRA_ISIS_NETLINK_H
#define _ZEBRA_ISIS_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>

#define TRILL_NL_VERSION 0x1
#define TRILL_NL_FAMILY  "TRILL_NL"
#define TRILL_MCAST_NAME "TR_NL_MCAST"
#define KERNL_RESPONSE_INTERFACE -1
#define PAGE_SHIFT		12
#define PAGE_SIZE		(1UL << PAGE_SHIFT)

struct trill_nl_header {
  int ifindex;  /* port id */
  int total_length; /* message total length for mutipart messages check */
  int msg_number; /* message number for multipart messages check */
};

enum{
  TRILL_ATTR_UNSPEC,
  TRILL_ATTR_U16,
  TRILL_ATTR_BIN,
  __TRILL_ATTR_MAX,
};
#define TRILL_ATTR_MAX (__TRILL_ATTR_MAX-1)

/* GET and set are from user space perspective
 * example TRILL_CMD_GET_VLANS means that the kernel will
 * send this info to userspace
 */
enum{
  TRILL_CMD_UNSPEC,
  TRILL_CMD_SET_NICKS_INFO,
  TRILL_CMD_GET_NICKS_INFO,
  TRILL_CMD_ADD_NICKS_INFO,
  TRILL_CMD_DEL_NICK,
  TRILL_CMD_SET_TREEROOT_ID,
  TRILL_CMD_GET_RBRIDGE,
  TRILL_CMD_SET_RBRIDGE,
  TRILL_CMD_PORT_FLUSH,
  TRILL_CMD_NICK_FLUSH,
  __TRILL_CMD_MAX,
};
#define TRILL_CMD_MAX (__TRILL_CMD_MAX-1)
#define TRILL_NL_VERSION 0x1

extern int parse_cb(struct nl_msg *msg, void *data);
#endif
