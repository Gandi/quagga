#include <zebra.h>
#include <vty.h>
#include <if.h>

#include "dict.h"
#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "isisd.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_tlv.h"
#include "isisd/trill.h"
#include "privs.h"

void trill_init(int argc, char **argv){return;}
void trill_struct_init(struct isis_area *area){return;}
void trill_exit(){return;}
