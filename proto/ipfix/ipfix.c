/*
 *  BIRD -- IP Flow Information Export (IPFIX)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL
 */

#define LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/socket.h"
#include "lib/timer.h"

#include "ipfix.h"

static int ipfix_connect(struct ipfix_proto *proto);

static void ipfix_send_templates(struct ipfix_proto *proto)
{
  int len;

  DBG("IPFIX: Sending template\n");

  len = ipfix_fill_template(proto->sk, ++proto->sequence_number);

  if (proto->cfg->protocol == IPFIX_PROTO_UDP)
    sk_send_to(proto->sk, len, proto->cfg->dest, proto->cfg->port);
  else
    sk_send(proto->sk, len);

}

static void ipfix_counter_timer_hook(struct timer *t)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)t->data;

  DBG("IPFIX: Counter timer\n");

  if (proto->sk == NULL) {
    if (ipfix_connect(proto) != PS_UP)
      return;
  }

  /* TODO - Send counters */

  tm_start(t, proto->cfg->interval);
}

static void ipfix_template_timer_hook(struct timer *t)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)t->data;

  DBG("IPFIX: Template timer\n");

  if (proto->sk == NULL) {
    if (ipfix_connect(proto) != PS_UP)
      return;
  }

  ipfix_send_templates(proto);

  tm_start(t, proto->cfg->template_interval);
}

static void ipfix_init_timers(struct ipfix_proto *proto)
{
  if (proto->counter_timer == NULL) {
    proto->counter_timer = tm_new_set(
        proto->p.pool,
        ipfix_counter_timer_hook,
        proto,
        0,
        0);

    proto->template_timer = tm_new_set(
        proto->p.pool,
        ipfix_template_timer_hook,
        proto,
        0,
        0);

    ipfix_send_templates(proto);

    tm_start(proto->counter_timer, proto->cfg->interval);
    tm_start(proto->template_timer, proto->cfg->template_interval);
  }
}

static void ipfix_tx_hook(sock *sk)
{
  /* We are connected */

  struct ipfix_proto *proto;

  DBG("IPFIX: Connected\n");

  sk->tx_hook = NULL;

  proto = (struct ipfix_proto *)sk->data;
  proto_notify_state(&proto->p, PS_UP);

  ipfix_init_timers(proto);
}

static void ipfix_err_hook(sock *sk, int err)
{
  /* Connection failed */

  struct ipfix_proto *proto;

  DBG("IPFIX: Error\n");

  proto = (struct ipfix_proto *)sk->data;
  proto->sk = NULL;

  /* Terminate socket, but attempt to reconnect at next interval */
  rfree(sk);

  proto_notify_state(&proto->p, PS_DOWN);
}

static int ipfix_connect(struct ipfix_proto *proto)
{
  struct ipfix_config *cfg = proto->cfg;
  sock *sk;

  DBG("IPFIX: Connecting\n");

  sk = sk_new(proto->p.pool);
  sk->data = proto;
  sk->saddr = cfg->source;
  sk->daddr = cfg->dest;
  sk->dport = cfg->port;

  sk->tx_hook = ipfix_tx_hook;
  sk->err_hook = ipfix_err_hook;

  proto->sk = sk;

  if (cfg->protocol == IPFIX_PROTO_UDP) {
    sk->type = SK_UDP;
    sk_set_tbsize(sk, 512);

    if (sk_open(sk) < 0)
      return PS_DOWN;
    else {
      ipfix_tx_hook(sk);
      return PS_UP;
    }
  }
  else {
    int ret;

    sk->type = SK_TCP;
    sk_set_tbsize(sk, 65536);
  
    ret = sk_open(sk);
    if (ret == 0)
      return PS_START;
    else if (ret < 0)
      return PS_DOWN;
    else
      return PS_UP;
  }
}

static struct proto *ipfix_init(struct proto_config *c)
{
  struct proto *p = proto_new(c, sizeof(struct ipfix_proto));
  struct ipfix_config *cfg = (struct ipfix_config *)c;
  struct ipfix_proto *proto = (struct ipfix_proto *)p;

  proto->cfg = cfg;
  proto->sk = NULL;
  proto->counter_timer = NULL;
  proto->template_timer = NULL;

  return p;
}

static int ipfix_start(struct proto *p)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)p;
  return ipfix_connect(proto);
}

static int ipfix_shutdown(struct proto* p)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)p;

  rfree(proto->sk);
  rfree(proto->counter_timer);
  rfree(proto->template_timer);

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
