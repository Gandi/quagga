#include <zebra.h>

#include "log.h"
#include "linklist.h"
#include "stream.h"
#include "memory.h"
#include "prefix.h"
#include "vty.h"
#include "if.h"

#include "isisd/dict.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_tlv.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_pdu.h"
#include "isisd/isis_lsp.h"
#include "isisd/trill.h"

int add_subtlv (u_char tag, u_char len, u_char * value, size_t tlvpos,
    struct stream *stream)
{
  unsigned newlen;

  /* Compute new outer TLV length */
  newlen = stream_getc_from(stream, tlvpos + 1) + (unsigned) len + TLFLDS_LEN;

  /* Check if it's possible to fit the subTLV in the stream at all */
  if (STREAM_SIZE (stream) - stream_get_endp (stream) <
      (unsigned) len + TLFLDS_LEN ||
      len > 255 - TLFLDS_LEN)
    {
      zlog_warn ("No room for subTLV %d len %d", tag, len);
      return ISIS_ERROR;
    }

  /* Check if it'll fit in the current TLV */
  if (newlen > 255)
    {
      /* extreme debug only, because repeating TLV is usually possible */
      zlog_warn ("No room for subTLV %d len %d in TLV %d", tag, len,
                  stream_getc_from(stream, tlvpos));
      return ISIS_WARNING;
    }

  stream_putc (stream, tag);    /* TAG */
  stream_putc (stream, len);    /* LENGTH */
  stream_put (stream, value, (int) len);        /* VALUE */
  stream_putc_at (stream,  tlvpos + 1, newlen);

  return ISIS_OK;
}

/*
 * Add TLVs necessary to advertise TRILL nickname using router capabilities TLV
 */
int tlv_add_trill_nickname(struct trill_nickname *nick_info,
				   struct stream *stream,
				   struct  isis_area *area)
{
  size_t tlvstart;
  struct router_capability_tlv rtcap;
  u_char tflags;
  struct trill_nickname_subtlv tn;
  int rc;
  tlvstart = stream_get_endp (stream);
  (void) memset(&rtcap, 0, sizeof (rtcap));
  rc = add_tlv(ROUTER_CAPABILITY, sizeof ( struct router_capability_tlv),
		   (u_char *)&rtcap, stream);
  if (rc != ISIS_OK){
    return rc;}
  tflags = TRILL_FLAGS_V0;
  rc = add_subtlv (RCSTLV_TRILL_FLAGS, sizeof (tflags), (u_char *)&tflags,
      tlvstart, stream);
  if (rc != ISIS_OK)
    return rc;
  tn.tn_priority = nick_info->priority;  /*8 bits*/
  tn.tn_nickname = nick_info->name; /*16 bits*/
  tn.tn_trootpri = htons(area->trill->root_priority); /*16 bits*/
  tn.tn_treecount = htons(0); /*16 bits*/
  rc = add_subtlv (RCSTLV_TRILL_NICKNAME,
			 sizeof (struct trill_nickname_subtlv),(u_char *)&tn,
			 tlvstart, stream);

  return rc;
}
