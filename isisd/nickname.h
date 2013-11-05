
#ifndef _ZEBRA_ISIS_NICKNAME_H
#define _ZEBRA_ISIS_NICKANME_H
#include "isisd/trill.h"
#include <libtrill.h>


/* IETF TRILL protocol defined constants */
#define DFLT_NICK_PRIORITY 0x40   /* Default priority for autogen nicks */
#define DFLT_NICK_ROOT_PRIORITY 0x40  /* Default priority for autogen nicks */
/* MSB of priority set if nick is configured */
#define CONFIGURED_NICK_PRIORITY 0x80
 /* MSB of priority set if nick is configured */
#define CONFIGURED_NICK_ROOT_PRIORITY 0x80
#define MIN_RBRIDGE_PRIORITY 1     /* Min priority of use value */
#define MAX_RBRIDGE_PRIORITY 127   /* Max priority of use value */
#define MIN_RBRIDGE_ROOT_PRIORITY 1      /* Min root priority of use value */
#define MAX_RBRIDGE_ROOT_PRIORITY 65534  /* Max root priority of use value*/
/* Max RBridges possible */
#define MAX_RBRIDGE_NODES (RBRIDGE_NICKNAME_MAX + 1)
#define TRILL_NICKNAME_LEN   2       /* 16-bit nickname */
#define TRILL_DFLT_ROOT_PRIORITY 0x40    /* Default tree root priority */

/* Constants used in nickname generation/allocation */
#define NICKNAMES_BITARRAY_SIZE (MAX_RBRIDGE_NODES / 8) /* nick usage array */
/* stores nicks available per 32 nicks in nick bitarray */
#define CLEAR_BITARRAY_ENTRYLEN 4
#define CLEAR_BITARRAY_ENTRYLENBITS (4*8)  /* 32 nicks tracked in each entry */
#define CLEAR_BITARRAY_SIZE (MAX_RBRIDGE_NODES / CLEAR_BITARRAY_ENTRYLENBITS)

/* Vector with bits set to indicate nicknames in use */
static u_char nickbitvector[NICKNAMES_BITARRAY_SIZE];
#define	NICK_IS_USED(n)		(nickbitvector[(n)/8] & (1<<((n)%8)))
#define	NICK_SET_USED(n)	(nickbitvector[(n)/8] |= (1<<((n)%8)))
#define	NICK_CLR_USED(n)	(nickbitvector[(n)/8] &= ~(1<<((n)%8)))

/* Number of zero bits in each word of vector */
static u_char clear_bit_count[CLEAR_BITARRAY_SIZE];
int is_nickname_used(u_int16_t);
void trill_nickname_reserve(u_int16_t nick_nbo);
void trill_nickname_free(u_int16_t nick_nbo);
u_int16_t trill_nickname_alloc(void);
int  nickname_init(void);
void trill_nickinfo_del(struct nickinfo *);
int nick_cmp(const void *, const void *);
int sysid_cmp(const void *, const void *);
#endif
