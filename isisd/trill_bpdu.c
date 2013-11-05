#include <zebra.h>

#include "memory.h"
#include "thread.h"
#include "linklist.h"
#include "log.h"
#include "stream.h"
#include "vty.h"
#include "hash.h"
#include "prefix.h"
#include "if.h"
#include "checksum.h"
#include "md5.h"

#include "isisd/dict.h"
#include "isisd/include-netbsd/iso.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_adjacency.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_network.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_dr.h"
#include "isisd/isis_tlv.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_pdu.h"
#include "isisd/iso_checksum.h"
#include "isisd/isis_csm.h"
#include "isisd/isis_events.h"
#include "isisd/trill.h"

int send_trill_hello (struct isis_circuit *circuit)
{
  struct isis_fixed_hdr fixed_hdr;
  struct isis_lan_hello_hdr hello_hdr;
  unsigned long len_pointer, length = 0;
  u_int32_t interval;
  int retval;

  if (circuit->is_passive)
    return ISIS_OK;

  if (circuit->interface->mtu == 0)
    {
      zlog_warn ("circuit has zero MTU");
      return ISIS_WARNING;
    }

  if (!circuit->snd_stream)
    circuit->snd_stream = stream_new (ISO_MTU (circuit));
  else
    stream_reset (circuit->snd_stream);
 fill_fixed_hdr_andstream (&fixed_hdr, L1_LAN_HELLO, circuit->snd_stream);
  /*
   * Fill TRILL Hello PDU header
   */
  memset (&hello_hdr, 0, sizeof (struct isis_lan_hello_hdr));
  interval = circuit->hello_multiplier[TRILL_LEVEL - 1] *
    circuit->hello_interval[TRILL_LEVEL - 1];
  if (interval > USHRT_MAX)
    interval = USHRT_MAX;
  hello_hdr.circuit_t = TRILL_LEVEL_TO_L1(circuit->is_type);
  memcpy (hello_hdr.source_id, isis->sysid, ISIS_SYS_ID_LEN);
  hello_hdr.hold_time = htons ((u_int16_t) interval);

  hello_hdr.pdu_len = 0;	/* Update the PDU Length later */
  len_pointer = stream_get_endp (circuit->snd_stream) + 3 + ISIS_SYS_ID_LEN;

  hello_hdr.prio = circuit->priority[TRILL_LEVEL - 1];
  memcpy (hello_hdr.lan_id, circuit->u.bc.trill_desig_is,
		  ISIS_SYS_ID_LEN + 1);
      stream_put (circuit->snd_stream, &hello_hdr, ISIS_LANHELLO_HDRLEN);

  /*
   * Then the variable length part.
   */

  /*  Area Addresses TLV */
  if (listcount (circuit->area->area_addrs) == 0)
    return ISIS_WARNING;
  if (tlv_add_area_addrs (circuit->area->area_addrs, circuit->snd_stream))
    return ISIS_WARNING;

  /*  LAN Neighbors TLV */
  if (circuit->circ_type == CIRCUIT_T_BROADCAST)
    {
      if (circuit->u.bc.lan_neighs[TRILL_LEVEL - 1] &&
          listcount (circuit->u.bc.lan_neighs[TRILL_LEVEL - 1]) > 0)
      if (tlv_add_lan_neighs (circuit->u.bc.lan_neighs[TRILL_LEVEL - 1],
                                circuit->snd_stream))
	  return ISIS_WARNING;
    }



  if (circuit->pad_hellos)
    if (tlv_add_padding (circuit->snd_stream))
      return ISIS_WARNING;

  length = stream_get_endp (circuit->snd_stream);
  /* Update PDU length */
  stream_putw_at (circuit->snd_stream, len_pointer, (u_int16_t) length);

  if (isis->debugs & DEBUG_ADJ_PACKETS)
    {
      if (circuit->circ_type == CIRCUIT_T_BROADCAST)
	{
	  zlog_debug ("ISIS-Adj (%s): Sent L%d LAN IIH on %s, length %ld",
		      circuit->area->area_tag, TRILL_LEVEL, circuit->interface->name,
		      /* FIXME: use %z when we stop supporting old compilers. */
		      length);
	}
      else
	{
	  zlog_debug ("ISIS-Adj (%s): Sent P2P IIH on %s, length %ld",
		      circuit->area->area_tag, circuit->interface->name,
		      /* FIXME: use %z when we stop supporting old compilers. */
		      length);
	}
      if (isis->debugs & DEBUG_PACKET_DUMP)
        zlog_dump_data (STREAM_DATA (circuit->snd_stream),
                        stream_get_endp (circuit->snd_stream));
    }

  retval = circuit->tx (circuit, TRILL_LEVEL);
  if (retval != ISIS_OK)
    zlog_err ("ISIS-Adj (%s): Send L%d IIH on %s failed",
              circuit->area->area_tag, TRILL_LEVEL, circuit->interface->name);

  return retval;
}


int send_trill_hello_thread (struct thread *thread)
{
  struct isis_circuit *circuit;
  int retval;

  circuit = THREAD_ARG (thread);
  assert (circuit);
  circuit->u.bc.t_send_lan_hello[TRILL_LEVEL - 1] = NULL;

  if (circuit->u.bc.run_dr_elect[TRILL_LEVEL - 1])
    retval = isis_dr_elect (circuit, TRILL_LEVEL);

  retval = send_trill_hello (circuit);

  /* set next timer thread */
  THREAD_TIMER_ON (master, circuit->u.bc.t_send_lan_hello[TRILL_LEVEL-1],
		   send_trill_hello_thread, circuit,
		   isis_jitter (circuit->hello_interval[TRILL_LEVEL-1], IIH_JITTER));
  return retval;
}

int process_trill_hello (struct isis_circuit *circuit, u_char * ssnpa)
{
  int retval = ISIS_OK;
  struct isis_lan_hello_hdr hdr;
  struct isis_adjacency *adj;
  u_int32_t expected = 0, found = 0, auth_tlv_offset = 0;
  struct tlvs tlvs;
  u_char *snpa;
  struct listnode *node;

  if (isis->debugs & DEBUG_ADJ_PACKETS)
    {
      zlog_debug ("ISIS-Adj (%s): Rcvd L%d LAN IIH on %s, cirType %s, "
                  "cirID %u",
                  circuit->area->area_tag, TRILL_LEVEL, circuit->interface->name,
                  circuit_t2string (circuit->is_type), circuit->circuit_id);
      if (isis->debugs & DEBUG_PACKET_DUMP)
        zlog_dump_data (STREAM_DATA (circuit->rcv_stream),
                        stream_get_endp (circuit->rcv_stream));
    }

  if (circuit->circ_type != CIRCUIT_T_BROADCAST)
    {
      zlog_warn ("lan hello on non broadcast circuit");
      return ISIS_WARNING;
    }

  if ((stream_get_endp (circuit->rcv_stream) -
       stream_get_getp (circuit->rcv_stream)) < ISIS_LANHELLO_HDRLEN)
    {
      zlog_warn ("Packet too short");
      return ISIS_WARNING;
    }

  if (circuit->ext_domain)
    {
      zlog_debug ("TRILL_LEVEL %d LAN Hello received over circuit with "
		  "externalDomain = true", TRILL_LEVEL);
      return ISIS_WARNING;
    }

  /*
   * Fill the header
   */
  hdr.circuit_t = L1_LEVEL_TO_TRILL(stream_getc (circuit->rcv_stream));
  stream_get (hdr.source_id, circuit->rcv_stream, ISIS_SYS_ID_LEN);
  hdr.hold_time = stream_getw (circuit->rcv_stream);
  hdr.pdu_len = stream_getw (circuit->rcv_stream);
  hdr.prio = stream_getc (circuit->rcv_stream);
  stream_get (hdr.lan_id, circuit->rcv_stream, ISIS_SYS_ID_LEN + 1);

  if (hdr.pdu_len < (ISIS_FIXED_HDR_LEN + ISIS_LANHELLO_HDRLEN) ||
      hdr.pdu_len > ISO_MTU(circuit) ||
      hdr.pdu_len > stream_get_endp (circuit->rcv_stream))
    {
      zlog_warn ("ISIS-Adj (%s): Rcvd LAN IIH from (%s) with "
                 "invalid pdu length %d",
                 circuit->area->area_tag, circuit->interface->name,
                 hdr.pdu_len);
      return ISIS_WARNING;
    }

  /*
   * Set the stream endp to PDU length, ignoring additional padding
   * introduced by transport chips.
   */
  if (hdr.pdu_len < stream_get_endp (circuit->rcv_stream))
    stream_set_endp (circuit->rcv_stream, hdr.pdu_len);

  if (hdr.circuit_t != IS_LEVEL_1 &&
      hdr.circuit_t != IS_LEVEL_2 &&
      hdr.circuit_t != IS_LEVEL_1_AND_2 &&
      (TRILL_LEVEL & hdr.circuit_t) == 0)
    {
      zlog_err ("Level %d LAN Hello with Circuit Type %d", TRILL_LEVEL,
                hdr.circuit_t);
      return ISIS_ERROR;
    }

  /*
   * Then get the tlvs
   */
  expected |= TLVFLAG_AUTH_INFO;
  expected |= TLVFLAG_AREA_ADDRS;
  expected |= TLVFLAG_LAN_NEIGHS;

  auth_tlv_offset = stream_get_getp (circuit->rcv_stream);
  retval = parse_tlvs (circuit->area->area_tag,
                       STREAM_PNT (circuit->rcv_stream),
                       hdr.pdu_len - ISIS_LANHELLO_HDRLEN - ISIS_FIXED_HDR_LEN,
                       &expected, &found, &tlvs,
                       &auth_tlv_offset);

  if (retval > ISIS_WARNING)
    {
      zlog_warn ("parse_tlvs() failed");
      goto out;
    }

  if (!(found & TLVFLAG_AREA_ADDRS))
    {
      zlog_warn ("No Area addresses TLV in Level %d LAN IS to IS hello",
		 TRILL_LEVEL);
      retval = ISIS_WARNING;
      goto out;
    }

  if (!memcmp (hdr.source_id, isis->sysid, ISIS_SYS_ID_LEN))
    {
      zlog_warn ("ISIS-Adj (%s): duplicate system ID on interface %s",
		 circuit->area->area_tag, circuit->interface->name);
      return ISIS_WARNING;
    }

  /*
   * Accept the TRILL_LEVEL  adjacency only if a match between local and
   * remote area addresses is found
   */
  if (listcount (circuit->area->area_addrs) == 0 ||
      (area_match (circuit->area->area_addrs, tlvs.area_addrs) == 0))
    {
      if (isis->debugs & DEBUG_ADJ_PACKETS)
	{
	  zlog_debug ("ISIS-Adj (%s): Area mismatch, TRILL_LEVEL %d IIH on %s",
		      circuit->area->area_tag, TRILL_LEVEL,
		      circuit->interface->name);
	}
      retval = ISIS_OK;
      goto out;
    }

  /*
   * it's own IIH PDU - discard silently
   */
  if (!memcmp (circuit->u.bc.snpa, ssnpa, ETH_ALEN))
    {
      zlog_debug ("ISIS-Adj (%s): it's own IIH PDU - discarded",
		  circuit->area->area_tag);

      retval = ISIS_OK;
      goto out;
    }

  adj = isis_adj_lookup (hdr.source_id, circuit->u.bc.adjdb[TRILL_LEVEL - 1]);
  if ((adj == NULL) || (memcmp(adj->snpa, ssnpa, ETH_ALEN)) ||
      (adj->level != TRILL_LEVEL))
    {
      if (!adj)
        {
          /*
           * Do as in 8.4.2.5
           */
          adj = isis_new_adj (hdr.source_id, ssnpa, TRILL_LEVEL, circuit);
          if (adj == NULL)
            {
              retval = ISIS_ERROR;
              goto out;
            }
        }
      else
        {
          if (ssnpa) {
            memcpy (adj->snpa, ssnpa, 6);
          } else {
            memset (adj->snpa, ' ', 6);
          }
          adj->level = TRILL_LEVEL;
        }
      isis_adj_state_change (adj, ISIS_ADJ_INITIALIZING, NULL);

      adj->sys_type = ISIS_SYSTYPE_L1_IS;

	list_delete_all_node (circuit->u.bc.lan_neighs[TRILL_LEVEL - 1]);
      isis_adj_build_neigh_list (circuit->u.bc.adjdb[TRILL_LEVEL - 1],
                                 circuit->u.bc.lan_neighs[TRILL_LEVEL - 1]);
    }

  if(adj->dis_record[TRILL_LEVEL-1].dis==ISIS_IS_DIS)
  if (memcmp (circuit->u.bc.trill_desig_is, hdr.lan_id, ISIS_SYS_ID_LEN + 1))
  {
	thread_add_event (master, isis_event_dis_status_change, circuit, 0);
	memcpy (&circuit->u.bc.trill_desig_is, hdr.lan_id,
	ISIS_SYS_ID_LEN + 1);
  }

  adj->hold_time = hdr.hold_time;
  adj->last_upd = time (NULL);
  adj->prio[TRILL_LEVEL - 1] = hdr.prio;

  memcpy (adj->lanid, hdr.lan_id, ISIS_SYS_ID_LEN + 1);

  tlvs_to_adj_area_addrs (&tlvs, adj);

  adj->circuit_t = hdr.circuit_t;

  /* lets take care of the expiry */
  THREAD_TIMER_OFF (adj->t_expire);
  THREAD_TIMER_ON (master, adj->t_expire, isis_adj_expire, adj,
                   (long) adj->hold_time);

  /*
   * If the snpa for this circuit is found from LAN Neighbours TLV
   * we have two-way communication -> adjacency can be put to state "up"
   */

  if (found & TLVFLAG_LAN_NEIGHS)
  {
    if (adj->adj_state != ISIS_ADJ_UP)
    {
      for (ALL_LIST_ELEMENTS_RO (tlvs.lan_neighs, node, snpa))
      {
        if (!memcmp (snpa, circuit->u.bc.snpa, ETH_ALEN))
        {
          isis_adj_state_change (adj, ISIS_ADJ_UP,
                                 "own SNPA found in LAN Neighbours TLV");
        }
      }
    }
    else
    {
      int found = 0;
      for (ALL_LIST_ELEMENTS_RO (tlvs.lan_neighs, node, snpa))
        if (!memcmp (snpa, circuit->u.bc.snpa, ETH_ALEN))
        {
          found = 1;
          break;
        }
      if (found == 0)
        isis_adj_state_change (adj, ISIS_ADJ_INITIALIZING,
                               "own SNPA not found in LAN Neighbours TLV");
    }
  }
  else if (adj->adj_state == ISIS_ADJ_UP)
  {
    isis_adj_state_change (adj, ISIS_ADJ_INITIALIZING,
                           "no LAN Neighbours TLV found");
  }

out:
  if (isis->debugs & DEBUG_ADJ_PACKETS)
    {
      zlog_debug ("ISIS-Adj (%s): Rcvd L%d LAN IIH from %s on %s, cirType %s, "
		  "cirID %u, length %ld",
		  circuit->area->area_tag,
		  TRILL_LEVEL, snpa_print (ssnpa), circuit->interface->name,
		  circuit_t2string (circuit->is_type),
		  circuit->circuit_id,
		  stream_get_endp (circuit->rcv_stream));
    }

  free_tlvs (&tlvs);

  return retval;
}
