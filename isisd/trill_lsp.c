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
#include "isisd/netlink.h"
#include "isisd/nickname.h"
#include "command.h"
#include "privs.h"

static int trill_parse_lsp (struct isis_lsp *lsp, struct nickinfo *recvd_nick)
{
  struct listnode *node;
  struct router_capability *rtr_cap;
  u_int8_t subtlvs_len;
  u_int8_t subtlv;
  u_int8_t subtlv_len;
  u_int8_t stlvlen;
  u_int16_t dtroot_nick;
  bool nick_recvd = false;
  bool flags_recvd = false;
  u_char *pnt;

  memset(recvd_nick, 0, sizeof(struct nickinfo));
  if (lsp->tlv_data.router_capabilities == NULL)
    return false;

  memcpy (recvd_nick->sysid, lsp->lsp_header->lsp_id, ISIS_SYS_ID_LEN);
  recvd_nick->root_priority = TRILL_DFLT_ROOT_PRIORITY;

  for (ALL_LIST_ELEMENTS_RO (lsp->tlv_data.router_capabilities, node, rtr_cap))
    {
       if (rtr_cap->len < ROUTER_CAPABILITY_MIN_LEN)
         continue;
       subtlvs_len = rtr_cap->len - ROUTER_CAPABILITY_MIN_LEN;
       pnt = ((u_char *)rtr_cap) + sizeof(struct router_capability);

	 while (subtlvs_len >= TLFLDS_LEN){
	   subtlv = *(u_int8_t *)pnt++; subtlvs_len--;
	   subtlv_len = *(u_int8_t *)pnt++; subtlvs_len--;
	   if (subtlv_len > subtlvs_len){
               zlog_warn("ISIS trill_parse_lsp received invalid router"
	         " capability subtlvs_len:%d subtlv_len:%d",
		 subtlvs_len, subtlv_len);
               break;
	   }

	   switch (subtlv){
	     case RCSTLV_TRILL_FLAGS:
	       stlvlen = subtlv_len;
	       /* minimal LSP length is one Byte
		  */
	       if (!flags_recvd && subtlv_len >= TRILL_FLAGS_SUBTLV_MIN_LEN){
	         recvd_nick->flags = *(u_int8_t *)pnt;
	         flags_recvd = true;
		 }
	       else{
		   if (flags_recvd)
                     zlog_warn("ISIS trill_parse_lsp multiple TRILL"
				    " flags sub-TLVs received");
		   else
                     zlog_warn("ISIS trill_parse_lsp invalid len:%d"
				    " of TRILL flags sub-TLV", subtlv_len);
		 }
	       pnt += stlvlen;
             subtlvs_len -= subtlv_len;
	       break;

	     case RCSTLV_TRILL_NICKNAME:
	       stlvlen = subtlv_len;
	       if (!nick_recvd && subtlv_len >= TRILL_NICKNAME_SUBTLV_MIN_LEN){
		   struct trill_nickname_subtlv *tn;
		   tn = (struct trill_nickname_subtlv *)pnt;
                   recvd_nick->nick.priority = tn->tn_priority;
	         recvd_nick->nick.name = tn->tn_nickname;
		   recvd_nick->root_priority = ntohs(tn->tn_trootpri);
		   recvd_nick->root_count = ntohs(tn->tn_treecount);
		   nick_recvd = true;
		 }
	       else{
		   if (nick_recvd)
                     zlog_warn("ISIS trill_parse_lsp multiple TRILL"
				    " nick sub-TLVs received");
		   else
                     zlog_warn("ISIS trill_parse_lsp invalid len:%d"
				    " of TRILL nick sub-TLV", subtlv_len);
		 }
               pnt += stlvlen;
               subtlvs_len -= subtlv_len;
	       break;

	     case RCSTLV_TRILL_TREE:
		 /* TODO */
	       break;

	     case RCSTLV_TRILL_TREE_ROOTS:
		 if (subtlv_len % TRILL_NICKNAME_LEN){
                   pnt += subtlv_len;
			 subtlvs_len -= subtlv_len;
                   zlog_warn("ISIS trill_parse_lsp received invalid"
		     " distribution tree roots subtlv_len:%d", subtlv_len);
			 break;

		}
	       if (recvd_nick->dt_roots == NULL)
                 recvd_nick->dt_roots = list_new();
	       stlvlen = subtlv_len;  /* zero len possible */
		 while (stlvlen > 0){
                   dtroot_nick = *(u_int16_t *)pnt;
			 pnt += TRILL_NICKNAME_LEN;
			 subtlvs_len -= TRILL_NICKNAME_LEN;
			 stlvlen -= TRILL_NICKNAME_LEN;
                   if (dtroot_nick == RBRIDGE_NICKNAME_NONE ||
		       dtroot_nick == RBRIDGE_NICKNAME_UNUSED){
                       zlog_warn("ISIS trill_parse_lsp received invalid"
			 " distribution tree root nick:%d.", dtroot_nick);
                       continue;
		      }
		       listnode_add (recvd_nick->dt_roots,
				     (void *)(u_long)*(u_int16_t *)pnt);
	      }
	       break;
	     case RCSTLV_TRILL_TREE_ROOTS_ID:
		 /* TODO */
	       break;
	     case RCSTLV_TRILL_VERSION:
		 /* TODO */
	       break;
	     default:
	       stlvlen = subtlv_len;
	       pnt += subtlv_len;
	       subtlvs_len -= subtlv_len;
	       break;
	     }
      }
    }
  return (nick_recvd);
}


static void trill_nick_recv(struct isis_area *area,
				    struct nickinfo *other_nick)
{
  struct nickinfo ournick;
  int nickchange = false;

  ournick.nick = area->trill->nick;
  memcpy (ournick.sysid, area->isis->sysid, ISIS_SYS_ID_LEN);

  /* Check for reserved TRILL nicknames that are not valid for use */
  if ((other_nick->nick.name == RBRIDGE_NICKNAME_NONE) ||
	  (other_nick->nick.name == RBRIDGE_NICKNAME_UNUSED))
    {
       return;
    }

  if (!(other_nick->flags & TRILL_FLAGS_V0))
    {
      return;
    }

  /* Check for conflict with our own nickname */
  if (other_nick->nick.name == area->trill->nick.name)
    {
       /* Check if our nickname has lower priority or our
	* system ID is lower, if not we keep our nickname.
	*/
       if (!(nickchange = trill_nick_conflict (&ournick, other_nick)))
          return;
    }

  /* Update our nick database */
  trill_nickdb_update (area, other_nick);

  if (nickchange)
     {
       /* We choose another nickname */
       trill_nickname_gen (area);
        SET_FLAG(area->trill->status, TRILL_AUTONICK);
	/* If previous nick was configured remove the bit
	 * indicating nickname was configured  (0x80) */
	area->trill->nick.priority &= ~CONFIGURED_NICK_PRIORITY;
      lsp_regenerate_schedule (area, TRILL_LEVEL, 1);
     }
}

/*
 * Remove nickname from the database.
 * Called from lsp_destroy or when lsp is missing a nickname TLV
 */
void trill_lsp_destroy_nick(struct isis_lsp *lsp, bool lsp_parsed)
{
  u_char *lsp_id;
  struct nickinfo ni;
  struct isis_area *area;
  int delnick;

  if (!isis->trill_active)
	  return;

  area = listgetdata(listhead (isis->area_list));
  lsp_id = lsp->lsp_header->lsp_id;

  /*
   * If LSP is our own or is a Pseudonode LSP (and we do not
   * learn nicks from Pseudonode LSPs) then no action is needed.
   */
  if ((memcmp (lsp_id, isis->sysid, ISIS_SYS_ID_LEN) == 0) ||
	(LSP_PSEUDO_ID(lsp_id) != 0))
	  return;
  /* avoid parsing LSP again if already done by calling function */
  if (lsp_parsed ||
	  !trill_parse_lsp (lsp, &ni) ||
	  (ni.nick.name == RBRIDGE_NICKNAME_NONE))
    {
      /* Delete the nickname associated with the LSP system ID
       * (if any) that did not include router capability TLV or
       * TRILL flags or the nickname in the LSP is unknown. This
       * happens when we recv a LSP from RBridge that just re-started
       * and we have to delete the prev nick associated with it.
       */
      trill_dict_delete_nodes(area->trill->sysidtonickdb,
					area->trill->nickdb,
					lsp_id,
					true);
      if(!lsp_parsed)
         trill_nickinfo_del (&ni);
      return;
    }

  memcpy(ni.sysid, lsp_id, ISIS_SYS_ID_LEN);
  delnick = ntohs(ni.nick.name);
  if (delnick != RBRIDGE_NICKNAME_NONE &&
	  delnick != RBRIDGE_NICKNAME_UNUSED &&
	  ni.nick.priority >= MIN_RBRIDGE_PRIORITY)
    {
      /* Only delete if the nickname was learned
       * from the LSP by ensuring both system ID
       * and nickname in the LSP match with a node
       * in our nick database.
       */
      if (trill_search_rbridge (area, &ni, NULL) == DUPLICATE)
        {
           trill_dict_delete_nodes (area->trill->sysidtonickdb,
						area->trill->nickdb,
						ni.sysid,
						true);
	}
    }
  trill_nickinfo_del (&ni);
}

void trill_parse_router_capability_tlvs (struct isis_area *area,
						     struct isis_lsp *lsp)
{
  struct nickinfo recvd_nick;

  /* Return if LSP is our own or is a pseudonode LSP */
  if ((memcmp (lsp->lsp_header->lsp_id, isis->sysid, ISIS_SYS_ID_LEN) == 0)
       || (LSP_PSEUDO_ID(lsp->lsp_header->lsp_id) != 0))
    return;

  if (trill_parse_lsp (lsp, &recvd_nick))
    {
      /* Parsed LSP correctly but process only if nick is not unknown */
      if (recvd_nick.nick.name != RBRIDGE_NICKNAME_NONE)
         trill_nick_recv(area, &recvd_nick);
    }
  else
    {
       /* if we have a nickname stored from this RBridge we remove it as this
	* LSP without a nickname likely indicates the RBridge has re-started
	* and hasn't chosen a new nick.
        */
       trill_lsp_destroy_nick (lsp, true);
    }
}
