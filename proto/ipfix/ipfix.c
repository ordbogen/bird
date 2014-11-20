/*
 *  BIRD -- IP Flow Information Export (IPFIX)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL
 */

/**
 * DOC: IP Flow Information Export
 *
 * The IPFIX protocol is implemented in two files: |ipfix.c| handles the
 * overall protocol and scheduling of IPFIX packets, !packets! handles
 * encoding of IPFIX packets,
 *
 * The IPFIX protocol is essentially just a couple of timers, handling
 * template retransmission and data transmission respectively.
 *
 * IPFIX in BIRD can run over either UDP or TCP. The consequence of this
 * is that we must handle whatever MTU the underlying protocol restrict
 * us to. When we want to send either the templates or the data, we
 * generate all the packets and then starts flushing the queue.
 */

#define LOCAL_DEBUG

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/socket.h"
#include "lib/timer.h"

#include "ipfix.h"

static int ipfix_connect(struct ipfix_proto *proto);
static void ipfix_flush_queue(struct ipfix_proto *proto);

static struct ipfix_packet *ipfix_new_packet(struct ipfix_proto *proto)
{
  struct ipfix_packet *packet;
  if (!EMPTY_LIST(proto->unused_packets))
  {
    packet = (struct ipfix_packet *)HEAD(proto->unused_packets);
    rem2_node(&packet->n);
  }
  else {
    packet = (struct ipfix_packet *)mb_alloc(proto->p.pool, sizeof(*packet) + proto->cfg->mtu);
  }

  return packet;
}

static inline void ipfix_discard_packet(struct ipfix_proto *proto, struct ipfix_packet *packet)
{
  rem2_node(&packet->n);
  add_head(&proto->unused_packets, &packet->n);
}

static inline void ipfix_queue_packet(struct ipfix_proto *proto, struct ipfix_packet *packet)
{
  add_tail(&proto->pending_packets, &packet->n);
}

static void ipfix_tx_hook(sock *sk)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)sk->data;

  DBG("IPFIX: ipfix_tx_hook\n");

  sk->tx_hook = NULL;

  if (EMPTY_LIST(proto->pending_packets))
    return;

  ipfix_discard_packet(proto, (struct ipfix_packet *)HEAD(proto->pending_packets));
  
  sk_set_tbuf(sk, NULL);

  ipfix_flush_queue(proto);
}

static void ipfix_flush_queue(struct ipfix_proto *proto)
{
  DBG("ipfix_flush_queue()\n");

  if (proto->sk->tx_hook != NULL)
    return;

  while (!EMPTY_LIST(proto->pending_packets)) {
    struct ipfix_packet *packet = (struct ipfix_packet *)HEAD(proto->pending_packets);
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

    ipfix_discard_packet(proto, packet);

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
    struct ipfix_packet *packet;

    packet = ipfix_new_packet(proto);
    packet->len = ipfix_fill_template(
        packet->data,
        packet->data + proto->cfg->mtu,
        proto->cfg->observation_domain_id,
        ++proto->sequence_number,
        &template_offset,
        &option_template_offset,
        &flow_id_offset,
        &type_info_offset);

    ipfix_queue_packet(proto, packet);

    ++count;
  }

  ipfix_flush_queue(proto);
}

static void ipfix_send_counters(struct ipfix_proto *proto)
{
  int proto_offset = 0;
  int system_offset = 0;

  DBG("ipfix_send_counters()\n");

  if (proto->sk == NULL)
  {
    if (ipfix_connect(proto) != PS_UP)
      return;
  }

  while (proto_offset != -1)
  {
    struct ipfix_packet *packet;

    packet = ipfix_new_packet(proto);
    packet->len = ipfix_fill_counters(
        packet->data,
        packet->data + proto->cfg->mtu,
        proto->cfg->observation_domain_id,
        ++proto->sequence_number,
        proto->cfg->reduced_template,
        &proto_offset,
        &system_offset);

    ipfix_queue_packet(proto, packet);
  }

  ipfix_flush_queue(proto);
}


static void ipfix_counter_timer_hook(struct timer *t)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)t->data;

  DBG("ipfix_counter_timer_hook()\n");

  ipfix_send_counters(proto);

  tm_start(t, proto->cfg->data_interval);
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

    tm_start(proto->counter_timer, proto->cfg->data_interval);
  }

  if (proto->cfg->protocol != IPFIX_PROTO_TCP) {
    proto->template_timer = tm_new_set(
        proto->p.pool,
        ipfix_template_timer_hook,
        proto,
        0,
        0);

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
  init_list(&proto->unused_packets);

  return p;
}

static int ipfix_start(struct proto *p)
{
  struct ipfix_proto *proto = (struct ipfix_proto *)p;

  DBG("ipfix_start()\n");

  ipfix_init_timers(proto);

  return PS_START;
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
  .copy_config =  ipfix_copy_config
};
