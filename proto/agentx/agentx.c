/*
 *  BIRD -- Agent Extensibility (AgentX) Protocol
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "agentx.h"
#include "packets.h"

#define HASH_PACKET_ID_FN(_key)				(_key)
#define HASH_PACKET_ID_EQ(_key1,_key2)		((_key1) == (_key2))
#define HASH_PACKET_ID_NEXT(_node)			((_node)->bucket_next)
#define HASH_PACKET_ID_KEY(_node)			((_node)->packet_id)

#define HASH_PACKET_ORDER	8

static void agentx_operation_free(struct agentx_proto *p, agentx_operation *oper)
{
  snmp_varbind *varbind, *next;

  HASH_REMOVE(p->response_hash, HASH_PACKET_ID, oper);
  rem_node(&oper->n);

  switch (oper->type)
  {
    case AGENTX_OPERATION_NOTIFY:
      mb_free(oper->payload.notify.oid);
      WALK_LIST_DELSAFE(varbind, next, oper->payload.notify.varbinds)
      {
        snmp_varbind_free(varbind);
      }
      break;

    case AGENTX_OPERATION_OPEN:
      break;
  }

  mb_free(oper);
}

static inline agentx_operation *agentx_operation_new(struct agentx_proto *p, agentx_operation_type type)
{
  agentx_operation *oper = (agentx_operation *)mb_allocz(p->p.pool, sizeof(*oper));
  oper->type = type;
  return oper;
}

/**
 * agentx_dequeue_operation - get next AgentX operation from queue
 * @p: AgentX instance
 *
 * This function takes the next operation in queue, populates
 * it with a packet id and a timestamp and moves it to the response
 * hash and list.
 *
 * The function is called from the packet code which is expected
 * to transmit the packet onto the wire after dequeing
 */
agentx_operation *agentx_dequeue_operation(struct agentx_proto *p)
{
  agentx_operation *oper = (agentx_operation *)p->queue.head;
  if (oper != NULL)
    rem_node(&oper->n);

  oper->timestamp = now;
  oper->packet_id = p->next_packet_id++;

  HASH_INSERT(p->response_hash, HASH_PACKET_ID, oper);
  add_tail(&p->response_list, &oper->n);

  return oper;
}

static void agentx_enqueue_operation(struct agentx_proto *p, agentx_operation *oper)
{
  add_tail(&p->queue, &oper->n);

  if (p->sk->tx_hook == NULL)
    agentx_tx(p->sk);
}

/**
 * agentx_set_response - register response code
 * @p: AgentX instance
 * @packet_id: Packet id to register the response to
 * @error: AgentX error code
 * @index: AgentX index
 */
void agentx_set_response(struct agentx_proto *p, u32 packet_id, u16 error, u16 index)
{
  agentx_operation *oper = HASH_FIND(p->response_hash, HASH_PACKET_ID, packet_id);
  if (oper == NULL)
    return;

  /* TODO - Print to log if something fails */

  agentx_operation_free(p, oper);
}

static void agentx_register_hook(snmp_protocol *snmp, const snmp_registration *registration)
{
  struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
  if (p->state == AGENTX_STATE_ESTABLISHED)
  {
    /* TODO */
  }
}

static void agentx_unregister_hook(snmp_protocol *snmp, const snmp_registration *registration)
{
  struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
  if (p->state == AGENTX_STATE_ESTABLISHED)
  {
    /* TODO */
  }
}

static void agentx_notify_hook(snmp_protocol *snmp, const u32 *oid, unsigned int oidlen, const list *varbinds)
{
  struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
  if (p->state == AGENTX_STATE_ESTABLISHED)
  {
    const snmp_varbind *varbind;
    agentx_operation *oper = agentx_operation_new(p, AGENTX_OPERATION_NOTIFY);

    oper->payload.notify.timestamp = now;

    oper->payload.notify.oid = mb_alloc(p->p.pool, oidlen * sizeof(*oid));
    oper->payload.notify.oidlen = oidlen;
    memcpy(oper->payload.notify.oid, oid, oidlen * sizeof(*oid));

    init_list(&oper->payload.notify.varbinds);
    WALK_LIST(varbind, *varbinds)
    {
      snmp_varbind *varbind_copy = snmp_varbind_copy(p->p.pool, varbind);
      add_tail(&oper->payload.notify.varbinds, &varbind_copy->n);
    }

    agentx_enqueue_operation(p, oper);
  }
}

static struct proto *agentx_init(struct proto_config *C)
{
  struct agentx_proto *p = (struct agentx_proto *)proto_new(C, sizeof(*p));

  p->cf = (struct agentx_config *)C;

  p->snmp.register_hook = agentx_register_hook;
  p->snmp.unregister_hook = agentx_unregister_hook;
  p->snmp.notify_hook = agentx_notify_hook;
  p->snmp.user_data = (void *)p;

  p->state = AGENTX_STATE_DISABLED;
  p->sk = NULL;
  p->session_id = 0;
  p->next_packet_id = 1;

  init_list(&p->queue);
  HASH_INIT(p->response_hash, p->p.pool, HASH_PACKET_ORDER);
  init_list(&p->response_list);

  return &p->p;
}

static void agentx_connected_hook(sock *sk)
{
  struct agentx_proto *p = (struct agentx_proto *)sk->data;
  agentx_operation *oper = agentx_operation_new(p, AGENTX_OPERATION_OPEN);
  p->sk->rx_hook = agentx_rx;
  p->state = AGENTX_STATE_OPEN_SENT;
  agentx_enqueue_operation(p, oper);
}

static void agentx_err_hook(sock *sk UNUSED, int er UNUSED)
{
}

static int agentx_connect(struct agentx_proto *p)
{
  sock *sk;

  sk = sk_new(p->p.pool);
  if (p->cf->transport == AGENTX_TRANSPORT_TCP)
  {
    sk->type = SK_TCP_ACTIVE;
    sk->data = p;
    sk->saddr = IPA_NONE;
    sk->daddr = p->cf->agent.tcp.addr;
    sk->dport = p->cf->agent.tcp.port;
  }
  sk->tx_hook = agentx_connected_hook;
  sk->err_hook = agentx_err_hook;

  p->state = AGENTX_STATE_CONNECTING;
  p->sk = sk;
  if (sk_open(sk) < 0)
  {
    p->state = AGENTX_STATE_DISCONNECTED;
    return 0;
  }

  return 1;
}

static int agentx_start(struct proto *P)
{
  struct agentx_proto *p = (struct agentx_proto *)P;

  snmp_add_protocol(&p->snmp);

  if (agentx_connect(p))
    return PS_START;
  else
    return PS_DOWN;
}

static int agentx_shutdown(struct proto *P)
{
  struct agentx_proto *p = (struct agentx_proto *)P;

  /* TODO */

  snmp_remove_protocol(&p->snmp);

  return PS_DOWN;
}

struct protocol proto_agentx = {
  .name =			"AgentX",
  .template =			"agentx%d",
  .init =			agentx_init,
  .start =			agentx_start,
  .shutdown =			agentx_shutdown,
};
