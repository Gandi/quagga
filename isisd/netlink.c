/*
 * IS-IS Rout(e)ing protocol - netlink.c
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
#include "isisd/netlink.h"

static struct nla_policy TRILL_U16_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_U16] = {.type = NLA_U16},
};
static struct nla_policy TRILL_U32_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_U32] = {.type = NLA_U32},
};
static struct nla_policy TRILL_STRING_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_STRING] = {.type = NLA_STRING},
};
static struct nla_policy TRILL_BIN_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_BIN] = {.type = NLA_UNSPEC},
};

static struct nla_policy TRILL_VNI_POLICY [TRILL_ATTR_MAX + 1] = {
  [TRILL_ATTR_U16] = {.type = NLA_U16},
  [TRILL_ATTR_BIN] = {.type = NLA_UNSPEC},
};
int parse_cb(struct nl_msg *msg, void *data)
{
  struct genlmsghdr* genlh;
  struct trill_nl_header *tnlh;
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  struct nlattr *attrs[TRILL_ATTR_MAX + 1];
  struct isis_area *area = (struct isis_area *) data;
  /* Validate message and parse attributes */
  genlh = nlmsg_data(nlh);
  uint32_t bridge_id;
  tnlh = (struct trill_nl_header *)genlmsg_data(genlh);
  if(tnlh->ifindex != KERNL_RESPONSE_INTERFACE)
    return 0;
  switch (genlh->cmd){
    case TRILL_CMD_SET_DESIG_VLAN:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		     TRILL_ATTR_MAX, TRILL_U32_POLICY);
      break;
    }
    case TRILL_CMD_SET_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_GET_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_ADD_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_DEL_NICK:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, NULL);
      break;
    }
    case TRILL_CMD_SET_TREEROOT_ID:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_U16_POLICY);
      break;
    }
    case TRILL_CMD_NEW_BRIDGE:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_STRING_POLICY);
      break;
    }
    case TRILL_CMD_GET_BRIDGE:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_U16_POLICY);
      break;
    }
    case TRILL_CMD_SET_BRIDGE:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_U16_POLICY);
      break;
    }
    case TRILL_CMD_LIST_NICK:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_PORT_FLUSH:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, NULL);
      break;
    }
    case TRILL_CMD_NICK_FLUSH:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_U16_POLICY);
      break;
    }
    case TRILL_CMD_GET_VNIS:
    {
      int16_t vni_nb;
      uint32_t vnis[MAX_VNI_ARR_SIZE];
      int i;
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs,
		    TRILL_ATTR_MAX, TRILL_VNI_POLICY);
      vni_nb = nla_get_u16(attrs[TRILL_ATTR_U16]);
      if (attrs[TRILL_ATTR_U32]) {
           bridge_id = nla_get_u32(attrs[TRILL_ATTR_U32]);
           if (area->bridge_id != bridge_id)
               return 0;
	   }
      nla_memcpy(vnis,attrs[TRILL_ATTR_BIN], sizeof(uint32_t)*vni_nb);
      list_delete(area->trill->configured_vni);
      area->trill->configured_vni = list_new();
      for (i=0; i< vni_nb; i++)
     listnode_add(area->trill->configured_vni, (void *)(u_long)vnis[i]);
      if (generate_supported_vni(area))
	lsp_regenerate_now(area, TRILL_ISIS_LEVEL);
      break;
    }
    default:
    {
      zlog_warn("received unknown command\n");
      break;
    }
  }
  return 0;
}

int rcvbuf = 1024 * 1024;
void rtnl_close(struct rtnl_handle *rth)
{
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}

int rtnl_open(struct rtnl_handle *rth, unsigned subscriptions)
{
	socklen_t addr_len;
	int sndbuf = 32768;

	memset(rth, 0, sizeof(*rth));

	rth->proto = NETLINK_ROUTE;
	rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (rth->fd < 0) {
		zlog_warn("rtnetlink: Cannot open netlink socket");
		return -1;
	}
	if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0) {
		zlog_warn("rtnetlink: SO_SNDBUF");
		return -1;
	}

	if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
		zlog_warn("rtnetlink: SO_RCVBUF");
		return -1;
	}

	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;

	if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0) {
		zlog_warn("rtnetlink: Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0) {
		zlog_warn("rtnetlink: Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		zlog_warn("rtnetlink: Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		zlog_warn("rtnelink: Wrong address family %d\n", rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;

}

int accept_msg(const struct sockaddr_nl *who,
                      struct nlmsghdr *n, void *arg)
{
	struct rtattr * RTVNIS;
	struct rtattr * tb[IFLA_MAX+1];
	struct rtattr *rta;
	struct ifinfomsg *ifi;
	int len = n->nlmsg_len;
	uint32_t *vnis;
	int nb;
	int i;
	unsigned short type;
	struct isis_area *area = (struct isis_area *) arg;

	if (n->nlmsg_type != RTM_NEWLINK)
		return 0;
	ifi = NLMSG_DATA(n);
	if (ifi->ifi_family != AF_BRIDGE)
		return 0;
	if (ifi->ifi_index != area->bridge_id)
		return 0;
	len -= NLMSG_LENGTH(sizeof(*ifi));

	if (len < 0) {
		zlog_warn("rtnetlink: message is too short!\n");
		return -1;
	}

	rta = IFLA_RTA(ifi);
	memset(tb, 0, sizeof(struct rtattr *) * (IFLA_MAX + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type;
		if ((type == IFLA_TRILL_VNI && !tb[type]))
			tb[type] = rta;
		else if (type == IFLA_TRILL_VNI && !tb[type])
			zlog_warn("rtnetlink: duplicated VNI entry!\n");
		rta = RTA_NEXT(rta,len);
        }

	if(tb[IFLA_TRILL_VNI]) {
		RTVNIS = tb[IFLA_TRILL_VNI];
		len = RTA_PAYLOAD(RTVNIS);
		vnis = calloc(len, 1);
		memcpy(vnis, RTA_DATA(RTVNIS), len);
		nb = len / sizeof(uint32_t);
		if (area->trill->configured_vni)
		list_delete(area->trill->configured_vni);
		area->trill->configured_vni = list_new();
		for (i=0; i< nb; i++)
			listnode_add(area->trill->configured_vni, (void *)(u_long)vnis[i]);
		if (generate_supported_vni(area))
			lsp_regenerate_now(area, TRILL_ISIS_LEVEL);

	} else {
		zlog_warn("rtnetlink: no VNI attribute found\n");
	}
	return;
}

int rtnl_listen(struct rtnl_handle *rtnl, void *arg)
{
	int status;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[16384];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;
	nladdr.nl_pid = 0;
	nladdr.nl_groups = 0;

	iov.iov_base = buf;
	iov.iov_len = sizeof(buf);
	status = recvmsg(rtnl->fd, &msg, 0);

	if (status < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;
		/* zlog_warn("rtnetlink: receive error %s (%d)\n",
			strerror(errno), errno);*/
		if (errno == ENOBUFS)
			return 0;
		return -1;
	}
	if (status == 0) {
		zlog_warn("rtnetlink: EOF on netlink\n");
		return -1;
	}
	if (msg.msg_namelen != sizeof(nladdr)) {
		zlog_warn("rtnetlink: Sender address length == %d\n", msg.msg_namelen);
		return -1;
	}
	for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
		int err;
		int len = h->nlmsg_len;
		int l = len - sizeof(*h);
		if (l<0 || len>status) {
			if (msg.msg_flags & MSG_TRUNC) {
				zlog_warn("rtnetlink: Truncated message\n");
				return -1;
			}
			zlog_warn("rtnetlink: !!!malformed message: len=%d\n", len);
			return -1;
		}
		err = accept_msg(&nladdr, h, arg);
		if (err < 0)
			return err;
		status -= NLMSG_ALIGN(len);
		h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
	}
	if (msg.msg_flags & MSG_TRUNC) {
		zlog_warn("rtnetlink: Message truncated\n");
		return 0;
	}
	if (status) {
		zlog_warn("rtnetlink: !!!Remnant of size %d\n", status);
		return -1;
	}

}


int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
		int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		zlog_warn("addattr_l ERROR: message exceeded bound of %d\n",maxlen);
		return -1;
        }
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}

struct rtattr *addattr_nest(struct nlmsghdr *n, int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	addattr_l(n, maxlen, type, NULL, 0);
	return nest;
}

int addattr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (void *)NLMSG_TAIL(n) - (void *)nest;
	return n->nlmsg_len;
}

int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
	      struct nlmsghdr *answer, size_t len)
{
	int status;
	unsigned seq;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr;
	struct iovec iov = {
		.iov_base = (void*) n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char   buf[32768];

	memset(&nladdr, 0, sizeof(nladdr));
	nladdr.nl_family = AF_NETLINK;

	n->nlmsg_seq = seq = ++rtnl->seq;

	if (answer == NULL)
		n->nlmsg_flags |= NLM_F_ACK;

	status = sendmsg(rtnl->fd, &msg, 0);
	if (status < 0) {
		zlog_warn("Cannot talk to rtnetlink");
		return -1;
	}

	memset(buf,0,sizeof(buf));

	iov.iov_base = buf;
	while (1) {
		iov.iov_len = sizeof(buf);
		status = recvmsg(rtnl->fd, &msg, 0);

		if (status < 0) {
			if (errno == EINTR || errno == EAGAIN)
				continue;
			zlog_warn("netlink receive error %s (%d)",
				strerror(errno), errno);
			return -1;
		}
		if (status == 0) {
			zlog_warn("EOF on netlink");
			return -1;
		}
		if (msg.msg_namelen != sizeof(nladdr)) {
			zlog_warn("sender address length == %d", msg.msg_namelen);
			return -1;
		}
		for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);

			if (l < 0 || len>status) {
				if (msg.msg_flags & MSG_TRUNC) {
					zlog_warn("Truncated message");
					return -1;
				}
				zlog_warn("!!!malformed message: len=%d", len);
				return -1;
			}

			if (nladdr.nl_pid != 0 ||
			    h->nlmsg_pid != rtnl->local.nl_pid ||
			    h->nlmsg_seq != seq) {
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
				continue;
			}

			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
				if (l < sizeof(struct nlmsgerr)) {
					zlog_warn("ERROR truncated");
				} else if (!err->error) {
					if (answer)
						memcpy(answer, h,
						       MIN(len, h->nlmsg_len));
					return 0;
				}

				zlog_warn("RTNETLINK answers: %s",
					strerror(-err->error));
				errno = err->error;
				return errno;
			}

			if (answer) {
				memcpy(answer, h,
				       MIN(len, h->nlmsg_len));
				return 0;
			}

			zlog_warn("Unexpected reply!!!");

			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
		}

		if (msg.msg_flags & MSG_TRUNC) {
			zlog_warn("Message truncated\n");
			continue;
		}

		if (status) {
			zlog_warn("!!!Remnant of size %d", status);
			return -1;
		}
	}
}
