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
  u32 sysUpTime;
  u16 error;
  u16 index;
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
  static const u32 prefix[] = {1, 3, 6, 1, 2};
  struct agentx_object_id *buffer = (struct agentx_object_id *)ptr;

  if (oidlen > 5 && oid[5] < 256 && memcmp(oid, prefix, sizeof(prefix)) == 0)
  {
    if (ptr + sizeof(struct agentx_object_id) + (oidlen - 6) * sizeof(*oid) > end)
      return 0;

    oid += 6;
    oidlen -= 6;

    buffer->n_subid = oidlen;
    buffer->prefix = oid[5];
    buffer->include = 0;
    buffer->reserved = 0;
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
 * Transmit AgentX-open-PDU
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
 * Transmit AgentX-notify-PDU
 */
static int agentx_tx_notify(struct agentx_conn *conn UNUSED, const agentx_operation *oper UNUSED)
{
  /* TODO */
  return 0;
}

void agentx_tx(struct birdsock *sk)
{
  struct agentx_conn *conn = (struct agentx_conn *)sk->data;
  
  for (;;)
  {
    agentx_operation *oper = agentx_dequeue_operation(conn);
    int res;
    if (oper == NULL)
      break;

    res = -1;
    switch (oper->type)
    {
      case AGENTX_OPERATION_OPEN:
	res = agentx_tx_open(conn, oper);
	break;

      case AGENTX_OPERATION_NOTIFY:
	res = agentx_tx_notify(conn, oper);
	break;
    }
    if (res <= 0)
      break;
  }
 
  if (EMPTY_LIST(conn->queue))
    sk->tx_hook = NULL;
}

static void agentx_rx_response(struct agentx_conn *conn, const byte *packet)
{
  const struct agentx_pdu_header *header = (const struct agentx_pdu_header *)packet;
  const struct agentx_response_pdu *payload = (const struct agentx_response_pdu *)(packet + sizeof(struct agentx_pdu_header));
  if (header->payload_length < sizeof(struct agentx_response_pdu))
    return;

  agentx_set_response(conn, header->packet_id, payload->error, payload->index);
}

static void agentx_rx_packet(struct agentx_conn *conn, const byte *packet)
{
  const struct agentx_pdu_header *header = (const struct agentx_pdu_header *)packet;
  if ((header->flags & AGENTX_FLAG_NON_DEFAULT_CONTEXT) != 0)
    return;

  if (header->type == AGENTX_RESPONSE_PDU)
    agentx_rx_response(conn, packet);
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
