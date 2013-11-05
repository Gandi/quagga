#include "netlink.h"

static struct nla_policy TRILL_U16_POLICY [TRILL_ATTR_MAX + 1]={
  [TRILL_ATTR_U16]={.type=NLA_U16},
};
static struct nla_policy TRILL_BIN_POLICY [TRILL_ATTR_MAX + 1]={
  [TRILL_ATTR_BIN]={.type=NLA_UNSPEC},
};

int parse_cb(struct nl_msg *msg, void *data)
{
  struct genlmsghdr* genlh;
  struct trill_nl_header *tnlh;
  struct nlmsghdr *nlh = nlmsg_hdr(msg);
  struct nlattr *attrs[TRILL_ATTR_MAX+1];
  struct isis_area *area= (struct isis_area *) data;
  /* Validate message and parse attributes */
  genlh=nlmsg_data(nlh);
  tnlh=(struct trill_nl_header *)genlmsg_data(genlh);
  if(tnlh->ifindex != KERNL_RESPONSE_INTERFACE)
    return 0;
  switch (genlh->cmd){
    case TRILL_CMD_SET_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_GET_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_ADD_NICKS_INFO:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,TRILL_BIN_POLICY);
      break;
    }
    case TRILL_CMD_DEL_NICK:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,NULL);
      break;
    }
    case TRILL_CMD_SET_TREEROOT_ID:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,TRILL_U16_POLICY);
      break;
    }
    case TRILL_CMD_GET_RBRIDGE:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,TRILL_U16_POLICY);
      u_int16_t nickname;
      if (attrs[TRILL_ATTR_U16]) {
		/*TODO*/

      }
      break;
    }
    case TRILL_CMD_SET_RBRIDGE:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,TRILL_U16_POLICY);
      break;
    }
    case TRILL_CMD_PORT_FLUSH:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,NULL);
      break;
    }
    case TRILL_CMD_NICK_FLUSH:
    {
      genlmsg_parse(nlh, sizeof(struct trill_nl_header), attrs, TRILL_ATTR_MAX,TRILL_U16_POLICY);
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
