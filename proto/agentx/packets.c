/*
 *  BIRD -- AgentX Packet Processing
 *
 *  (c) 2014 Peter Christensen <pch@ordbogen.com>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "agentx.h"

struct agentx_pdu_header
{
  u8 version;
  u8 type;
  u8 flags;
  u8 reserved;
  u32 session_id;
  u32 transaction_id;
  u32 packet_id;
  u32 payload_length;
};

enum agentx_pdu_type
{
  AGENTX_OPEN_PDU = 1,
  AGENTX_CLOSE_PDU = 2,
  AGENTX_REGISTER_PDU = 3,
  AGENTX_UNREGISTER_PDU = 4,
  AGENTX_GET_PDU = 5,
  AGENTX_GET_NEXT_PDU = 6,
  AGENTX_GET_BULK_PDU = 7,
  AGENTX_TEST_SET_PDU = 8,
  AGENTX_COMMIT_SET_PDU = 9,
  AGENTX_UNDO_SET_PDU = 10,
  AGENTX_CLEANUP_SET_PDU = 11,
  AGENTX_NOTIFY_PDU = 12,
  AGENTX_PING_PDU = 13,
  AGENTX_INDEX_ALLOCATE_PDU = 14,
  AGENTX_INDEX_DEALLOCATE_PDU = 15,
  AGENTX_ADD_AGENT_CAPS_PDU = 16,
  AGENTX_REMOVE_AGENT_CAPS_PDU = 17,
  AGENTX_RESPONSE_PDU = 18
};

enum agentx_varbind_type
{
  AGENTX_TYPE_INTEGER = 2,
  AGENTX_TYPE_OCTET_STRING = 4,
  AGENTX_TYPE_NULL = 5,
  AGENTX_TYPE_OBJECT_IDENTIFIER = 6,
  AGENTX_TYPE_IP_ADDRESS = 64,
  AGENTX_TYPE_COUNTER32 = 65,
  AGENTX_TYPE_GAUGE32 = 66,
  AGENTX_TYPE_TIME_TICKS = 67,
  AGENTX_TYPE_OPAQUE = 68,
  AGENTX_TYPE_COUNTER64 = 70,
  AGENTX_TYPE_NO_SUCH_OBJECT = 128,
  AGENTX_TYPE_NO_SUCH_INSTANCE = 129,
  AGENTX_TYPE_END_OF_MIB_VIEW = 130
};

enum agentx_flag
{
  AGENTX_FLAG_INSTANCE_REGISTRATION = (1 << 0),
  AGENTX_FLAG_NEW_INDEX = (1 << 1),
  AGENTX_FLAG_ANY_INDEX = (1 << 2),
  AGENTX_FLAG_NON_DEFAULT_CONTEXT = (1 << 3),
  AGENTX_FLAG_NETWORK_BYTE_ORDER = (1 << 4)
};

struct agentx_open_pdu
{
  u8 timeout;
  u8 reserved[3];
};

struct agentx_response_pdu
{
  u32 sys_up_time;
  u16 error;
  u16 index;
};

struct agentx_close_pdu
{
  u8 reason;
  u8 reserved[3];
};

struct agentx_varbind
{
  u16 type;
  u16 reserved;
};

struct agentx_object_id
{
  u8 n_subid;
  u8 prefix;
  u8 include;
  u8 reserved;
  u32 subid[0];
};

struct agentx_string
{
  u32 length;
  u8 data[0];
};

/*
 * Encode Object Identifier
 */
static byte *agentx_encode_object_id(byte *ptr, byte *end, const u32 *oid, unsigned int oidlen)
{
  static const u32 prefix[] = {1, 3, 6, 1};
  struct agentx_object_id *buffer = (struct agentx_object_id *)ptr;

  if (oidlen > OID_LEN(prefix) && oid[OID_LEN(prefix)] != 0 && oid[OID_LEN(prefix)] < 256 && memcmp(oid, prefix, sizeof(prefix)) == 0)
  {
    if (ptr + sizeof(struct agentx_object_id) + (oidlen - OID_LEN(prefix) - 1) * sizeof(*oid) > end)
      return 0;

    oidlen -= OID_LEN(prefix) + 1;

    buffer->n_subid = oidlen;
    buffer->prefix = oid[OID_LEN(prefix)];
    buffer->include = 0;
    buffer->reserved = 0;
    
    oid += OID_LEN(prefix) + 1;
  }
  else
  {
    if (ptr + sizeof(struct agentx_object_id) + oidlen * sizeof(*oid) > end)
      return 0;

    buffer->n_subid = oidlen;
    buffer->prefix = 0;
    buffer->include = 0;
    buffer->reserved = 0;
  }

  memcpy(buffer->subid, oid, oidlen * sizeof(*oid));

  return ptr + sizeof(struct agentx_object_id) + oidlen * sizeof(*oid);
}

/*
 * Encode string
 */
static byte *agentx_encode_string(byte *ptr, byte *end, const char *string, unsigned int length)
{
  struct agentx_string *buffer = (struct agentx_string *)ptr;

  if (ptr + sizeof(struct agentx_string) + length > end)
    return 0;

  buffer->length = length;
  memcpy(buffer->data, string, length);

  return ptr + sizeof(struct agentx_string) + length;
}

static inline byte *agentx_encode_integer32(byte *ptr, byte *end, u32 value)
{
  if (end - ptr < sizeof(u32))
    return NULL;
  *(u32 *)ptr = value;
  return ptr + 4;
}

/*
 * Encode varbind
 */
static byte *agentx_encode_varbind(byte *ptr, byte *end, const snmp_varbind *varbind)
{
  struct agentx_varbind *header;

  if (end - ptr < sizeof(struct agentx_varbind))
    return NULL;

  header = (struct agentx_varbind *)ptr;
  header->reserved = 0;
  ptr += sizeof(struct agentx_varbind);

  ptr = agentx_encode_object_id(ptr, end, varbind->oid, varbind->oidlen);
  if (ptr == NULL)
    return NULL;

  switch (varbind->type)
  {
    case SNMP_TYPE_INTEGER32:
      header->type = AGENTX_TYPE_INTEGER;
      return agentx_encode_integer32(ptr, end, varbind->value.integer32);

    case SNMP_TYPE_OCTET_STRING:
      header->type = AGENTX_TYPE_OCTET_STRING;
      return agentx_encode_string(ptr, end, varbind->value.string.str, varbind->value.string.size);

    case SNMP_TYPE_NULL:
      header->type = AGENTX_TYPE_NULL;
      return ptr;

    case SNMP_TYPE_OBJECT_IDENTIFIER:
      header->type = AGENTX_TYPE_OBJECT_IDENTIFIER;
      return agentx_encode_object_id(ptr, end, varbind->value.oid.oid, varbind->value.oid.size);

    case SNMP_TYPE_IP_ADDRESS:
      header->type = AGENTX_TYPE_IP_ADDRESS;
      /* TODO */
      return NULL;

    case SNMP_TYPE_COUNTER32:
      header->type = AGENTX_TYPE_COUNTER32;
      return agentx_encode_integer32(ptr, end, varbind->value.counter32);

    case SNMP_TYPE_GAUGE32:
      header->type = AGENTX_TYPE_GAUGE32;
      return agentx_encode_integer32(ptr, end, varbind->value.gauge32);

    case SNMP_TYPE_TIME_TICKS:
      header->type = AGENTX_TYPE_TIME_TICKS;
      return agentx_encode_integer32(ptr, end, varbind->value.time_ticks);

    case SNMP_TYPE_OPAQUE:
      header->type = AGENTX_TYPE_OPAQUE;
      /* TODO */
      return NULL;

    case SNMP_TYPE_COUNTER64:
      if (end - ptr < sizeof(u64))
        return NULL;
      header->type = AGENTX_TYPE_COUNTER64;
      *(u64 *)ptr = varbind->value.counter64;
      return ptr + sizeof(u64);

    case SNMP_TYPE_NO_SUCH_OBJECT:
      header->type = AGENTX_TYPE_NO_SUCH_OBJECT;
      return ptr;

    case SNMP_TYPE_NO_SUCH_INSTANCE:
      header->type = AGENTX_TYPE_NO_SUCH_INSTANCE;
      return ptr;

    case SNMP_TYPE_END_OF_MIB_VIEW:
      header->type = AGENTX_TYPE_END_OF_MIB_VIEW;
      return ptr;
  }

  return NULL;
}



/*
 * Put AgentX header on the transmit buffer
 */
static byte *agentx_encode_header(byte *ptr, byte *end, enum agentx_pdu_type type, u32 session_id, u32 transaction_id, u32 packet_id)
{
  struct agentx_pdu_header *header = (struct agentx_pdu_header *)ptr;
  if (ptr + sizeof(struct agentx_pdu_header) > end)
    return 0;

  header->version = 1;
  header->type = type;
#ifdef CPU_BIG_ENDIAN
  header->flags = AGENTX_FLAG_NETWORK_BYTE_ORDER;
#else // CPU_BIG_ENDIAN
  header->flags = 0;
#endif // CPU_BIG_ENDIAN
  header->session_id = session_id;
  header->transaction_id = transaction_id;
  header->packet_id = packet_id;
  /* payload_length is updated at the end */

  return ptr + sizeof(struct agentx_pdu_header);
}

/*
 * Set the payload header according to the payload length
 */
static inline void agentx_update_header(byte *ptr, byte *end)
{
  struct agentx_pdu_header *header = (struct agentx_pdu_header *)ptr;
  header->payload_length = end - ptr - sizeof(struct agentx_pdu_header);
}

/*
 * Transmit Agentx-Open-PDU
 */
static int agentx_tx_open(struct agentx_conn *conn, const agentx_operation *oper)
{
  static const u32 subagent_id[] = {1, 3, 6, 1, 4, 1, 40446};
  static const char subagent_descr[] = "BIRD Internet Routing Daemon";
  byte *ptr, *end;
  struct agentx_open_pdu *open_pdu;

  ptr = conn->sk->tbuf;
  end = ptr + conn->sk->tbsize;

  ptr = agentx_encode_header(ptr, end, AGENTX_OPEN_PDU, 0, 0, oper->packet_id);
  if (ptr == 0)
    return -1;

  if (ptr + sizeof(struct agentx_open_pdu) > end)
    return -1;

  open_pdu = (struct agentx_open_pdu *)ptr;
  open_pdu->timeout = 0; /* TODO */
  memset(&open_pdu->reserved, 0, sizeof(open_pdu->reserved));

  ptr += sizeof(struct agentx_open_pdu);

  ptr = agentx_encode_object_id(ptr, end, subagent_id, sizeof(subagent_id) / sizeof(subagent_id[0]));
  if (ptr == 0)
    return -1;

  ptr = agentx_encode_string(ptr, end, subagent_descr, strlen(subagent_descr));
  if (ptr == 0)
    return -1;

  agentx_update_header(conn->sk->tbuf, ptr);

  return sk_send(conn->sk, ptr - conn->sk->tbuf);
}

/*
 * Transmit Agentx-Notify-PDU
 */
static int agentx_tx_notify(struct agentx_conn *conn, const agentx_operation *oper)
{
  byte *ptr, *end;
  snmp_varbind *varbind;
  /* iso(1) org(3) dod(6) internet(1) mgmt(2) mib-2(1) system(1) sysUpTime(3) 0 */
  static const u32 sys_up_time[] =  {1, 3, 6, 1, 2, 1, 1, 3, 0};

  /* iso(1) org(3) dod(6) internet(1) snmpV2(6) snmpModules(3) snmpMIB(1) snmpMIBObjects(1) snmpTrap(4) snmpTrapOID(1) 0 */
  static const u32 sys_trap_oid[] = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};

  ptr = conn->sk->tbuf;
  end = ptr + conn->sk->tbsize;

  ptr = agentx_encode_header(ptr, end, AGENTX_NOTIFY_PDU, conn->session_id, 0, oper->packet_id);
  if (ptr == NULL)
    return -1;

  /* SNMPv2-MIB:sysUpTime.0 */
  varbind = snmp_varbind_new_time_ticks(conn->proto->p.pool, sys_up_time, OID_LEN(sys_up_time), 0, oper->payload.notify.timestamp);
  ptr = agentx_encode_varbind(ptr, end, varbind);
  snmp_varbind_free(varbind);
  if (ptr == NULL)
    return -1;

  /* SNMPv2-MIB:sysTrapOID.0 */
  varbind = snmp_varbind_new_object_id(conn->proto->p.pool, sys_trap_oid, OID_LEN(sys_trap_oid), 0, oper->payload.notify.oid, oper->payload.notify.oidlen);
  ptr = agentx_encode_varbind(ptr, end, varbind);
  snmp_varbind_free(varbind);
  if (ptr == NULL)
    return -1;

  WALK_LIST(varbind, oper->payload.notify.varbinds)
  {
    ptr = agentx_encode_varbind(ptr, end, varbind);
    if (ptr == NULL)
      return -1;
  }

  agentx_update_header(conn->sk->tbuf, ptr);

  return sk_send(conn->sk, ptr - conn->sk->tbuf);
}

/**
  * Transmit Agentx-Ping-PDU
  */
static int agentx_tx_ping(struct agentx_conn *conn, const agentx_operation *oper)
{
  byte *ptr, *end;

  ptr = conn->sk->tbuf;
  end = ptr + conn->sk->tbsize;

  ptr = agentx_encode_header(ptr, end, AGENTX_PING_PDU, conn->session_id, 0, oper->packet_id);
  if (ptr == NULL)
    return -1;

  agentx_update_header(conn->sk->tbuf, ptr);

  return sk_send(conn->sk, ptr - conn->sk->tbuf);
}

/*
 * Transmit Agentx-Response-PDU
 */
static int agentx_tx_response(struct agentx_conn *conn, const agentx_operation *oper)
{
  byte *ptr, *end;
  struct agentx_response_pdu *pdu;
  snmp_varbind *varbind;

  ptr = conn->sk->tbuf;
  end = ptr + conn->sk->tbsize;

  ptr = agentx_encode_header(ptr, end, AGENTX_RESPONSE_PDU, conn->session_id, 0, oper->packet_id);
  if (ptr == NULL)
    return -1;

  if (end - ptr < sizeof(struct agentx_response_pdu))
    return -1;

  pdu = (struct agentx_response_pdu *)ptr;
  pdu->sys_up_time = oper->payload.response.timestamp;
  pdu->error = oper->payload.response.error;
  pdu->index = oper->payload.response.index;
  ptr += sizeof(struct agentx_response_pdu);

  WALK_LIST(varbind, oper->payload.response.varbinds)
  {
    ptr = agentx_encode_varbind(ptr, end, varbind);
    if (ptr == NULL)
      return -1;
  }

  agentx_update_header(conn->sk->tbuf, ptr);

  return sk_send(conn->sk, ptr - conn->sk->tbuf);
}

/*
 * Transmit Agentx-Close-PDU
 */
static int agentx_tx_close(struct agentx_conn *conn, const agentx_operation *oper)
{
  byte *ptr, *end;
  struct agentx_close_pdu *pdu;

  ptr = conn->sk->tbuf;
  end = ptr + conn->sk->tbsize;

  ptr = agentx_encode_header(ptr, end, AGENTX_CLOSE_PDU, conn->session_id, 0, oper->packet_id);
  if (ptr == NULL)
    return -1;

  if (end - ptr < sizeof(struct agentx_close_pdu))
    return -1;

  pdu = (struct agentx_close_pdu *)ptr;
  pdu->reason = oper->payload.close.reason;
  memset(&pdu->reserved, 0, sizeof(pdu->reserved));
  ptr += sizeof(struct agentx_close_pdu);

  agentx_update_header(conn->sk->tbuf, ptr);

  return sk_send(conn->sk, ptr - conn->sk->tbuf);
}

void agentx_tx(struct birdsock *sk)
{
  struct agentx_conn *conn = (struct agentx_conn *)sk->data;
  
  for (;;)
  {
    agentx_operation *oper = agentx_get_operation_for_transmit(conn);
    int res;
    if (oper == NULL)
      break;

    res = -1;
    switch (oper->type)
    {
      case AGENTX_OPERATION_OPEN:
        res = agentx_tx_open(conn, oper);
        if (res >= 0)
          agentx_need_response(conn, oper);
	break;

      case AGENTX_OPERATION_NOTIFY:
        res = agentx_tx_notify(conn, oper);
        if (res >= 0)
          agentx_need_response(conn, oper);
	break;

      case AGENTX_OPERATION_PING:
        res = agentx_tx_ping(conn, oper);
        if (res >= 0)
          agentx_need_response(conn, oper);
        break;

      case AGENTX_OPERATION_RESPONSE:
        res = agentx_tx_response(conn, oper);
        agentx_operation_free(oper);
        break;

      case AGENTX_OPERATION_CLOSE:
        res = agentx_tx_close(conn, oper);
        agentx_operation_free(oper);
        break;
    }
    if (res <= 0)
      break;
  }
 
  if (EMPTY_LIST(conn->queue))
    sk->tx_hook = NULL;
}

/*
 * Handle Agentx-Response-PDU
 */
static void agentx_rx_response(struct agentx_conn *conn, const byte *packet)
{
  const struct agentx_pdu_header *header = (const struct agentx_pdu_header *)packet;
  const struct agentx_response_pdu *payload = (const struct agentx_response_pdu *)(packet + sizeof(struct agentx_pdu_header));
  agentx_operation *oper;
  if (header->payload_length < sizeof(struct agentx_response_pdu))
    return;

  oper = agentx_get_operation_for_response(conn, header->packet_id);
  if (oper == NULL)
    return;

  switch (oper->type)
  {
    case AGENTX_OPERATION_OPEN:
      agentx_rx_open_response(conn, payload->error, payload->index, header->session_id);
      break;

    case AGENTX_OPERATION_NOTIFY:
      /* TODO */
      break;

    case AGENTX_OPERATION_PING:
      /* TODO */
      break;

    case AGENTX_OPERATION_RESPONSE:
    case AGENTX_OPERATION_CLOSE:
      break;
  }

  agentx_operation_free(oper);
}

static void agentx_rx_packet(struct agentx_conn *conn, const byte *packet)
{
  const struct agentx_pdu_header *header = (const struct agentx_pdu_header *)packet;
  if ((header->flags & AGENTX_FLAG_NON_DEFAULT_CONTEXT) != 0)
    return;

  switch (header->type)
  {
    case AGENTX_RESPONSE_PDU:
      agentx_rx_response(conn, packet);
      break;

    case AGENTX_CLOSE_PDU:
      /* TODO */
      break;

    case AGENTX_GET_PDU:
    case AGENTX_GET_NEXT_PDU:
    case AGENTX_GET_BULK_PDU:
      /* TODO */
      break;

    case AGENTX_TEST_SET_PDU:
    case AGENTX_COMMIT_SET_PDU:
    case AGENTX_UNDO_SET_PDU:
    case AGENTX_CLEANUP_SET_PDU:
      break;
  }
}

int agentx_rx(struct birdsock *sk, int size)
{
  struct agentx_conn *conn = (struct agentx_conn *)sk->data;
  const byte *ptr = sk->rbuf;

  while (size >= sizeof(struct agentx_pdu_header))
  {
    const struct agentx_pdu_header *header = (const struct agentx_pdu_header *)ptr;
    if (header->version != 1)
    {
      /* Unsupported protocol version */
      /* TODO - Terminate connection */
      return 0;
    }

#ifdef CPU_BIG_ENDIAN
    if ((header->flags & AGENTX_FLAG_NETWORK_BYTE_ORDER) == 0)
#else // CPU_BIG_ENDIAN
    if ((header->flags & AGENTX_FLAG_NETWORK_BYTE_ORDER) != 0)
#endif // CPU_BIG_ENDIAN
    {
      /* Unsupported byte order */
      /* TODO - Terminate connection */
      return 0;
    }
    
    if (sizeof(struct agentx_pdu_header) + header->payload_length < size)
    {
      if (header->payload_length > conn->sk->rbsize - sizeof(struct agentx_pdu_header))
      {
        /* Packet too large for receive buffer */
        /* TODO */
      }
      return 0;
    }

    agentx_rx_packet(conn, ptr);

    ptr += sizeof(struct agentx_pdu_header) + header->payload_length;
    size -= sizeof(struct agentx_pdu_header) + header->payload_length;
  }

  if (ptr != sk->rbuf && size > 0)
  {
    memmove(sk->rbuf, ptr, size);
    sk->rpos = sk->rbuf + size;
  }
  
  return 0;  
}
