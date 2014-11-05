/*
 *  BIRD -- IP Flow Information Export (IPFIX)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL
 */

#undef LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/socket.h"
#include "lib/timer.h"

#include "ipfix.h"

static struct proto *ipfix_init(struct proto_config *cfg)
{
  struct proto *proto = proto_new(cfg, sizeof(struct ipfix_proto));
  struct ipfix_config *ipfix_cfg = (struct ipfix_config *)cfg;
  struct ipfix_proto *ipfix_proto = (struct ipfix_proto *)proto;

  ipfix_proto->cfg = ipfix_cfg;

  return proto;
}

static int ipfix_start(struct proto *proto)
{
  return PS_UP;
}

static int ipfix_shutdown(struct proto* proto)
{
  return PS_DOWN;
}

static void ipfix_copy_config(struct proto_config *dest, struct proto_config *src)
{
  /* Shallow copy of everything */
  proto_copy_rest(dest, src, sizeof(struct ipfix_config));
}

struct protocol proto_ipfix = {
  .name =         "IPFIX",
  .template =     "ipfix%d",
  .init =         ipfix_init,
  .start =        ipfix_start,
  .shutdown =     ipfix_shutdown,
  .copy_config =  ipfix_copy_config
};
