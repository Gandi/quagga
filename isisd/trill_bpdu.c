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
