/*
 *  BIRD -- Agent Extensibility (AgentX) Protocol
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "agentx.h"
#include "packets.h"

#define HASH_PACKET_ID_FN(_key)			(_key)
#define HASH_PACKET_ID_EQ(_key1,_key2)		((_key1) == (_key2))
#define HASH_PACKET_ID_NEXT(_node)		((_node)->bucket_next)
#define HASH_PACKET_ID_KEY(_node)		((_node)->packet_id)

#define HASH_PACKET_ORDER	8

void agentx_operation_free(agentx_operation *oper)
{
  snmp_varbind *varbind, *next;

  if (NODE_VALID(oper))
    rem2_node(&oper->n);

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
    case AGENTX_OPERATION_PING:
    case AGENTX_OPERATION_CLOSE:
      break;

    case AGENTX_OPERATION_RESPONSE:
      WALK_LIST_DELSAFE(varbind, next, oper->payload.response.varbinds)
      {
        snmp_varbind_free(varbind);
      }
      break;
  }

  mb_free(oper);
}

static inline agentx_operation *agentx_operation_new(pool *pool, agentx_operation_type type)
{
  agentx_operation *oper = (agentx_operation *)mb_allocz(pool, sizeof(*oper));
  oper->type = type;
  return oper;
}

/**
 * agentx_dequeue_operation - get next AgentX operation from queue
 * @conn: AgentX connection
 *
 * This function takes the next operation in queue and populates
 * it with a packet id and a timestamp.
 */
agentx_operation *agentx_get_operation_for_transmit(struct agentx_conn *conn)
{
  agentx_operation *oper = HEAD(conn->queue);
  if (!NODE_VALID(oper))
    return NULL;

  rem2_node(&oper->n);

  oper->timestamp = now;
  oper->packet_id = conn->next_packet_id++;

  return oper;
}

static void agentx_enqueue_operation(struct agentx_conn *conn, agentx_operation *oper)
{
  add_tail(&conn->queue, &oper->n);

  if (conn->sk->tx_hook == NULL)
    agentx_tx(conn->sk);
}

void agentx_need_response(struct agentx_conn *conn, agentx_operation *oper)
{
  HASH_INSERT(conn->response_hash, HASH_PACKET_ID, oper);
  add_tail(&conn->response_list, &oper->n);
}

agentx_operation *agentx_get_operation_for_response(struct agentx_conn *conn, u32 packet_id)
{
  agentx_operation *oper = HASH_FIND(conn->response_hash, HASH_PACKET_ID, packet_id);
  if (oper == NULL)
    return NULL;

  rem2_node(&oper->n);
  HASH_REMOVE(conn->response_hash, HASH_PACKET_ID, oper);

  return oper;
}

static void agentx_register_hook(snmp_protocol *snmp, const snmp_registration *registration)
{
  struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
  if (p->conn != NULL && p->conn->state == AGENTX_STATE_ESTABLISHED)
  {
    /* TODO */
  }
}

static void agentx_unregister_hook(snmp_protocol *snmp, const snmp_registration *registration)
{
  struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
  if (p->conn != NULL && p->conn->state == AGENTX_STATE_ESTABLISHED)
  {
    /* TODO */
  }
}

static void agentx_notify_hook(snmp_protocol *snmp, const u32 *oid, unsigned int oidlen, const list *varbinds)
{
  struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
  if (p->conn != NULL && p->conn->state == AGENTX_STATE_ESTABLISHED)
  {
    struct agentx_conn *conn = p->conn;
    const snmp_varbind *varbind;
    agentx_operation *oper = agentx_operation_new(p->p.pool, AGENTX_OPERATION_NOTIFY);

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

    agentx_enqueue_operation(conn, oper);
  }
}

void agentx_rx_open_response(struct agentx_conn *conn, u16 error, u16 index, u32 session_id)
{
  if (error == 0)
  {
    conn->session_id = session_id;
    conn->state = AGENTX_STATE_ESTABLISHED;

    proto_notify_state(&conn->proto->p, PS_UP);
  }
  else
  {
    /* Open failed */
    /* TODO */
  }
}

static void agentx_connected_hook(sock *sk)
{
  struct agentx_conn *conn = (struct agentx_conn *)sk->data;
  agentx_operation *oper;
  conn->sk->tx_hook = NULL;
  conn->sk->rx_hook = agentx_rx;
  conn->state = AGENTX_STATE_OPEN_SENT;

  oper = agentx_operation_new(conn->proto->p.pool, AGENTX_OPERATION_OPEN);
  agentx_enqueue_operation(conn, oper);
}

static void agentx_err_hook(sock *sk UNUSED, int er UNUSED)
{
}

static int agentx_connect(struct agentx_conn *conn)
{
  sock *sk;

  sk = sk_new(conn->proto->p.pool);
  if (conn->proto->cf->transport == AGENTX_TRANSPORT_TCP)
  {
    sk->type = SK_TCP_ACTIVE;
    sk->data = conn;
    sk->saddr = IPA_NONE;
    sk->daddr = conn->proto->cf->agent.tcp.addr;
    sk->dport = conn->proto->cf->agent.tcp.port;
  }
  sk->tx_hook = agentx_connected_hook;
  sk->err_hook = agentx_err_hook;
  sk->rbsize = 65536;
  sk->tbsize = 65536;

  conn->state = AGENTX_STATE_CONNECTING;
  conn->sk = sk;

  if (sk_open(sk) < 0)
  {
    conn->state = AGENTX_STATE_DISCONNECTED;
    return 0;
  }

  return 1;
}

static struct agentx_conn *agentx_conn_new(struct agentx_proto *p)
{
  struct agentx_conn *conn = (struct agentx_conn *)mb_allocz(p->p.pool, sizeof(*conn));
  conn->proto = p;
  conn->state = AGENTX_STATE_DISABLED;
  conn->next_packet_id = 1;
  init_list(&conn->queue);
  HASH_INIT(conn->response_hash, p->p.pool, HASH_PACKET_ORDER);
  init_list(&conn->response_list);
  return conn;
}

static int agentx_start(struct proto *P)
{
  struct agentx_proto *p = (struct agentx_proto *)P;

  snmp_add_protocol(&p->snmp);

  p->conn = agentx_conn_new(p);

  if (agentx_connect(p->conn))
    return PS_START;
  else
    return PS_DOWN;
}

static int agentx_shutdown(struct proto *P)
{
  struct agentx_proto *p = (struct agentx_proto *)P;

  /* TODO */

  snmp_remove_protocol(&p->snmp);

  p->conn = NULL;

  return PS_DOWN;
}

static struct proto *agentx_init(struct proto_config *C)
{
  struct agentx_proto *p = (struct agentx_proto *)proto_new(C, sizeof(*p));

  p->cf = (struct agentx_config *)C;

  p->snmp.register_hook = agentx_register_hook;
  p->snmp.unregister_hook = agentx_unregister_hook;
  p->snmp.notify_hook = agentx_notify_hook;
  p->snmp.user_data = (void *)p;

  p->conn = NULL;

  return &p->p;
}


struct protocol proto_agentx = {
  .name =			"AgentX",
  .template =		"agentx%d",
  .init =			agentx_init,
  .start =			agentx_start,
  .shutdown =		agentx_shutdown,
};
