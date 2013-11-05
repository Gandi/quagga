#include <zebra.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "thread.h"
#include "linklist.h"
#include "stream.h"
#include "vty.h"
#include "log.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "hash.h"
#include "if.h"
#include "table.h"
#include "privs.h"
#include "limits.h" /* add LINE_MAX const*/
#include "isisd/nickname.h"
#include "isisd/isis_constants.h"
int nickavailcnt = RBRIDGE_NICKNAME_MINRES - RBRIDGE_NICKNAME_NONE - 1;


int nickname_init(){
  u_int i;
  memset(nickbitvector, 0, sizeof(nickbitvector));
  for (i = 0; i < sizeof (clear_bit_count); i++)
	  clear_bit_count[i] = CLEAR_BITARRAY_ENTRYLENBITS;
  /* These two are always reserved */
  NICK_SET_USED(RBRIDGE_NICKNAME_NONE);
  NICK_SET_USED(RBRIDGE_NICKNAME_UNUSED);
  clear_bit_count[RBRIDGE_NICKNAME_NONE / CLEAR_BITARRAY_ENTRYLENBITS]--;
  clear_bit_count[RBRIDGE_NICKNAME_UNUSED / CLEAR_BITARRAY_ENTRYLENBITS]--;
}
static bool trill_nickname_nickbitmap_op(u_int16_t nick, int update, int val)
{
  if (nick == RBRIDGE_NICKNAME_NONE || nick == RBRIDGE_NICKNAME_UNUSED)
    return false;
  if (val)
  {
    if (NICK_IS_USED(nick))
      return true;
    if (!update)
      return false;
    NICK_SET_USED(nick);
    if (nick < RBRIDGE_NICKNAME_MINRES)
      nickavailcnt--;
    clear_bit_count[nick / CLEAR_BITARRAY_ENTRYLENBITS]--;
  }
  else
  {
    if (!NICK_IS_USED(nick))
      return true;
    if (!update)
      return false;
    NICK_CLR_USED(nick);
    if (nick < RBRIDGE_NICKNAME_MINRES)
      nickavailcnt++;
    clear_bit_count[nick / CLEAR_BITARRAY_ENTRYLENBITS]++;
  }
  return false;
}


u_int16_t trill_nickname_alloc(void)
{
  u_int i, j, k;
  u_int16_t nick;
  u_int16_t nicknum;
  u_int16_t freenickcnt = 0;
  if (nickavailcnt < 1) { return RBRIDGE_NICKNAME_NONE; }
  /*
   * Note that rand() usually returns 15 bits, so we overlap two values to make
   * sure we're getting at least 16 bits (as long as rand() returns 8 bits or
   * more).  Using random() instead would be better, but isis_main.c uses
   * srand.
   */
  nicknum = ((rand() << 8) | rand()) % nickavailcnt;
  for ( i = 0; i < sizeof (clear_bit_count); i++ )
  {
    freenickcnt += clear_bit_count[i];
    if (freenickcnt <= nicknum)  continue;
    nicknum -= freenickcnt - clear_bit_count[i];
    nick = i * CLEAR_BITARRAY_ENTRYLEN * 8;
    for ( j = 0; j < CLEAR_BITARRAY_ENTRYLEN; j++)
    {
      for (k = 0; k < 8; k++, nick++)
      {
	if (!NICK_IS_USED(nick) && nicknum-- == 0)
	{
	  trill_nickname_nickbitmap_op (nick, true, true);
	  return nick;
	}
      }
    }
    break;
  }
  return 0;
}

int is_nickname_used(u_int16_t nick_nbo)
{
  return trill_nickname_nickbitmap_op(ntohs(nick_nbo), false, true);
}
void trill_nickname_reserve(u_int16_t nick_nbo)
{
  trill_nickname_nickbitmap_op(ntohs(nick_nbo), true, true);
}

void trill_nickname_free(u_int16_t nick_nbo)
{
  trill_nickname_nickbitmap_op(ntohs(nick_nbo), true, false);
}
