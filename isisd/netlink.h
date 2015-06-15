/*
 * IS-IS Rout(e)ing protocol - netlink.h
 *
 * Copyright 2014 Gandi, SAS.  All rights reserved.
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

#ifndef _ZEBRA_ISIS_NETLINK_H
#define _ZEBRA_ISIS_NETLINK_H

#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/family.h>

#define TRILL_NL_VERSION 0x1
#define TRILL_NL_FAMILY  "TRILL_NL"
#define TRILL_MCAST_NAME "TR_NL_MCAST"
#define KERNL_RESPONSE_INTERFACE -1

struct trill_nl_header {
  /* port id */
  int ifindex;
  /* message total length for mutipart messages check */
  int total_length;
  /* message number for multipart messages check */
  int msg_number;
};

enum{
  TRILL_ATTR_UNSPEC,
  TRILL_ATTR_U16,
  TRILL_ATTR_U32,
  TRILL_ATTR_STRING,
  TRILL_ATTR_BIN,
  __TRILL_ATTR_MAX,
};
#define TRILL_ATTR_MAX (__TRILL_ATTR_MAX-1)

/*
 * GET and set are from user space perspective
 * example TRILL_CMD_GET_VLANS means that the kernel will
 * send this info to userspace
 */

enum{
  TRILL_CMD_UNSPEC,
  TRILL_CMD_SET_DESIG_VLAN,
  TRILL_CMD_SET_NICKS_INFO,
  TRILL_CMD_GET_NICKS_INFO,
  TRILL_CMD_ADD_NICKS_INFO,
  TRILL_CMD_DEL_NICK,
  TRILL_CMD_SET_TREEROOT_ID,
  TRILL_CMD_NEW_BRIDGE,
  TRILL_CMD_GET_BRIDGE,
  TRILL_CMD_SET_BRIDGE,
  TRILL_CMD_LIST_NICK,
  TRILL_CMD_PORT_FLUSH,
  TRILL_CMD_NICK_FLUSH,
  TRILL_CMD_GET_VNIS,
  __TRILL_CMD_MAX,
};
#define TRILL_CMD_MAX (__TRILL_CMD_MAX-1)

struct nl_req	{
	struct nlmsghdr		n;
	struct ifinfomsg	ifm;
	char			buf[1024];
	};

#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

#ifndef RTNLGRP_TRILL
 /*
  * We need to be really care full here in case
  * this group change in kernel side
  */
#define RTNLGRP_TRILL 27
#endif
#ifndef IFLA_TRILL_MAX
enum {
	IFLA_TRILL_UNSPEC,
	IFLA_TRILL_NICKNAME,
	IFLA_TRILL_ROOT,
	IFLA_TRILL_INFO,
	IFLA_TRILL_VNI,
	__IFLA_TRILL_MAX,
};
#define IFLA_TRILL_MAX (__IFLA_TRILL_MAX)
#endif

int init_netlink(struct nl_sock *,struct isis_area *);
int close_netlink(struct nl_sock *);
int parse_cb(struct nl_msg *msg, void *data);

int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions);
void rtnl_close(struct rtnl_handle *rth);
int rtnl_listen(struct rtnl_handle *rtnl, void *arg);
int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
		int alen);
struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type);
int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest);
int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
		struct nlmsghdr *answer, size_t len);
#endif
