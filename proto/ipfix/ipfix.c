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
static void ipfix_flush_queue(struct ipfix_proto *proto);
static int ipfix_shutdown(struct proto* p);

static void ipfix_tx_hook(sock *sk)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)sk->data;
  struct ipfix_pending_packet *packet;

  DBG("IPFIX: ipfix_tx_hook\n");

  sk->tx_hook = NULL;

  if (EMPTY_LIST(proto->pending_packets))
    return;

  packet = HEAD(proto->pending_packets);

  rem_node(&packet->n);
  mb_free(packet);
  
  sk_set_tbuf(sk, NULL);

  ipfix_flush_queue(proto);
}

static void ipfix_flush_queue(struct ipfix_proto *proto)
{
  DBG("ipfix_flush_queue()\n");

  if (proto->sk->tx_hook != NULL)
    return;

  while (!EMPTY_LIST(proto->pending_packets)) {
    struct ipfix_pending_packet *packet = HEAD(proto->pending_packets);
    int ret;

    sk_set_tbuf(proto->sk, &packet->data);

    if (proto->cfg->protocol == IPFIX_PROTO_TCP)
      ret = sk_send(proto->sk, packet->len);
    else
      ret = sk_send_to(proto->sk, packet->len, proto->cfg->dest, proto->cfg->port);

    if (ret == 0) {
      proto->sk->tx_hook = ipfix_tx_hook;
      return;
    }
    else if (ret <= 0)
      return;

    rem_node(&packet->n);
    mb_free(packet);

    sk_set_tbuf(proto->sk, NULL);
  }
}

static void ipfix_send_templates(struct ipfix_proto *proto)
{
  int template_offset = 0;
  int option_template_offset = 0;
  int flow_id_offset = 0;
  int type_info_offset = 0;
  int count = 0;

  DBG("ipfix_send_templates()\n");

  if (proto->sk == NULL)
  {
    if (ipfix_connect(proto) == 0)
      return;
  }

  while (template_offset != -1 || option_template_offset != -1 || flow_id_offset != -1 ||  type_info_offset != -1) {
    struct ipfix_pending_packet *packet;

    packet = (struct ipfix_pending_packet *)mb_alloc(proto->p.pool, sizeof(*packet) + proto->cfg->mtu);
    packet->len = ipfix_fill_template(
        packet->data,
        packet->data + proto->cfg->mtu,
        ++proto->sequence_number,
        &template_offset,
        &option_template_offset,
        &flow_id_offset,
        &type_info_offset);

    add_tail(&proto->pending_packets, &packet->n);

    ++count;
  }

  ipfix_flush_queue(proto);
}

static void ipfix_send_counters(struct ipfix_proto *proto)
{
  int proto_offset = 0;

  DBG("ipfix_send_counters()\n");

  if (proto->sk == NULL)
  {
    if (ipfix_connect(proto) != PS_UP)
      return;
  }

  while (proto_offset != -1)
  {
    struct ipfix_pending_packet *packet;

    packet = (struct ipfix_pending_packet *)mb_alloc(proto->p.pool, sizeof(*packet) + proto->cfg->mtu);
    packet->len = ipfix_fill_counters(
        packet->data,
        packet->data + proto->cfg->mtu,
        ++proto->sequence_number,
        &proto_offset,
        proto->cfg->reduced_template);

    add_tail(&proto->pending_packets, &packet->n);
  }

  ipfix_flush_queue(proto);
}


static void ipfix_counter_timer_hook(struct timer *t)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)t->data;

  DBG("ipfix_counter_timer_hook()\n");

  ipfix_send_counters(proto);

  tm_start(t, proto->cfg->interval);
}

static void ipfix_template_timer_hook(struct timer *t)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)t->data;

  DBG("ipfix_template_timer_hook()\n");

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

    tm_start(proto->counter_timer, proto->cfg->interval);
    tm_start(proto->template_timer, proto->cfg->template_interval);
  }
}

static void ipfix_tx_connect_hook(sock *sk)
{
  /* We are connected */

  struct ipfix_proto *proto;

  DBG("ipfix_tx_connect_hook()\n");

  sk->tx_hook = NULL;

  proto = (struct ipfix_proto *)sk->data;
  proto_notify_state(&proto->p, PS_UP);

  ipfix_send_templates(proto);
  ipfix_send_counters(proto);
}

static void ipfix_err_hook(sock *sk, int err)
{
  /* Connection failed */

  struct ipfix_proto *proto;

  DBG("ipfix_err_hook(%d)\n", err);

  sk->err_hook = NULL;
  sk->tx_hook = NULL;

  proto = (struct ipfix_proto *)sk->data;
  ipfix_shutdown(&proto->p);
  proto_notify_state(&proto->p, PS_DOWN);
}

static int ipfix_connect(struct ipfix_proto *proto)
{
  struct ipfix_config *cfg = proto->cfg;
  sock *sk;

  DBG("ipfix_connect()\n");

  sk = sk_new(proto->p.pool);
  sk->data = proto;
  sk->saddr = cfg->source;
  sk->daddr = cfg->dest;
  sk->dport = cfg->port;

  sk->tx_hook = ipfix_tx_connect_hook;
  sk->err_hook = ipfix_err_hook;

  proto->sk = sk;

  if (cfg->protocol == IPFIX_PROTO_UDP) {
    sk->type = SK_UDP;

    if (sk_open(sk) < 0)
      return 0;
    else {
      ipfix_tx_connect_hook(sk);
      return 1;
    }
  }
  else {
    sk->type = SK_TCP_ACTIVE;
  
    if (sk_open(sk) == 0)
      return 1;
    else
      return 0;
  }
}

static struct proto *ipfix_init(struct proto_config *c)
{
  struct proto *p = proto_new(c, sizeof(struct ipfix_proto));
  struct ipfix_config *cfg = (struct ipfix_config *)c;
  struct ipfix_proto *proto = (struct ipfix_proto *)p;

  DBG("ipfix_init()\n");

  proto->cfg = cfg;
  proto->sk = NULL;
  proto->counter_timer = NULL;
  proto->template_timer = NULL;
  proto->sequence_number = random_u32();
  init_list(&proto->pending_packets);

  return p;
}

static int ipfix_start(struct proto *p)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)p;

  DBG("ipfix_start()\n");

  ipfix_init_timers(proto);

  return PS_START;
}

static int ipfix_shutdown(struct proto* p)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)p;

  DBG("ipfix_shutdown()\n");

  rfree(proto->sk);
  proto->sk = NULL;

  rfree(proto->counter_timer);
  proto->counter_timer = NULL;

  rfree(proto->template_timer);
  proto->template_timer = NULL;

  // TODO - Free pending packets

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
