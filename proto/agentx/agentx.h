/*
 *  BIRD -- Agent Extensibility (AgentX) Protocol
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_AGENTX_H_
#define _BIRD_AGENTX_H_

#include "nest/protocol.h"
#include "nest/snmp.h"
#include "conf/conf.h"
#include "lib/socket.h"
#include "lib/hash.h"

struct agentx_tcp_agent
{
  ip_addr addr;
  int port;
};

struct agentx_unix_agent
{
  char path[108];
};

typedef union agentx_agent
{
  struct agentx_tcp_agent tcp;
} agentx_agent;

typedef enum _agentx_transport
{
  AGENTX_TRANSPORT_NONE,
  AGENTX_TRANSPORT_TCP,
  /* AGENTX_TRANSPORT_UNIX */
} agentx_transport;

struct agentx_config
{
  struct proto_config c;
  agentx_transport transport;
  agentx_agent agent;
  int timeout;
};

typedef enum _agentx_state
{
  AGENTX_STATE_DISABLED,
  AGENTX_STATE_DISCONNECTED,
  AGENTX_STATE_CONNECTING,
  AGENTX_STATE_OPEN_SENT,
  AGENTX_STATE_ESTABLISHED
} agentx_state;

typedef enum _agentx_operation_type
{
  AGENTX_OPERATION_OPEN,
  AGENTX_OPERATION_NOTIFY,
  AGENTX_OPERATION_PING,
  AGENTX_OPERATION_RESPONSE,
  AGENTX_OPERATION_CLOSE
} agentx_operation_type;

struct agentx_operation_notify
{
  /* Request data */
  bird_clock_t timestamp;
  u32 *oid;
  unsigned int oidlen;
  list varbinds;

  /* No response data */
};

struct agentx_operation_open
{
  /* No request data */

  /* Response data */
  u32 session_id;
};

struct agentx_operation_close
{
  /* Request data */
  u8 reason;

  /* No response data */
};

struct agentx_operation_response
{
  /* Request data */
  bird_clock_t timestamp;
  u16 error;
  u16 index;
  list varbinds;

  /* No response data */
};

typedef struct _agentx_operation agentx_operation;
struct agentx_conn;

typedef void (agentx_callback)(struct agentx_conn *conn, agentx_operation *oper, u16 error, u16 index);

struct _agentx_operation
{
  node n; /* Used when located in linked list */
  agentx_operation *bucket_next; /* Used when located in hash table */
  agentx_operation_type type;
  bird_clock_t timestamp;
  u32 packet_id;
  agentx_callback *callback;
  union
  {
    struct agentx_operation_open open;
    struct agentx_operation_notify notify;
    struct agentx_operation_close close;
    struct agentx_operation_response response;
  } payload;
};

struct agentx_conn
{
  struct agentx_proto *proto;

  agentx_state state;
  sock *sk; /* Valid in CONNECTION, OPEN_SENT, and ESTABLISHED states */
  u32 session_id; /* Valid only in ESTABLISHED state */
  u32 next_packet_id; /* Valid in OPEN_SENT and ESTABLISHED states */

  list queue; /* List of pending outgoing connections */

  HASH(agentx_operation) response_hash;
  list response_list;
};

struct agentx_proto
{
  struct proto p;
  struct agentx_config *cf;

  snmp_protocol snmp;

  struct agentx_conn *conn;
};

agentx_operation *agentx_dequeue_operation(struct agentx_conn *conn);
void agentx_need_response(struct agentx_conn *conn, agentx_operation *oper);
void agentx_set_response(struct agentx_conn *conn, u32 packet_id, u16 error, u16 index);

#endif // _BIRD_AGENTX_H_
