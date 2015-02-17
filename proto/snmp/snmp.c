/*
 *  BIRD -- Simple Network Management Protocol (SNMP)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "snmp.h"

struct snmp_cfg *snmp_cf = NULL;
struct snmp_proto *snmp_instance = NULL;

static void snmp_flush_queue(struct snmp_proto *snmp);

static void snmp_tx_hook(sock *socket)
{
  struct snmp_proto *snmp = (struct snmp_proto *)socket->data;
  struct snmp_payload *payload = HEAD(snmp->payload_list);

  socket->tx_hook = NULL;
  sk_set_tbuf(socket, NULL);

  rem_node(&payload->n);
  sl_free(snmp->payload_slab, payload);

  snmp_flush_queue(snmp);
}

static void snmp_err_hook(sock *socket, int err)
{
  struct snmp_proto *snmp = (struct snmp_proto *)socket->data;
  log(L_ERR "%s: Socket error: %s (%i)", snmp->p.name, strerror(err), err);
}

static sock *snmp_get_socket(struct snmp_proto *snmp)
{
  if (snmp->socket == NULL) {
    sock *sock = sock_new(snmp->p.pool);

    sock->type = SK_UDP;
    sock->err_hook = snmp_err_hook;
    sock->data = snmp;

    if (sk_open(sock) == -1)
    {
      rfree(sock);
      return NULL;
    }

    snmp->socket = sock;
  }

  return snmp->socket;
}

static void snmp_flush_queue(struct snmp_proto *snmp)
{
  while (!EMPTY_LIST(snmp->payload_list)) {
    struct snmp_payload *payload = HEAD(snmp->payload_list);

    sock *socket = snmp_get_socket(snmp);

    if (socket != NULL) {
      int err;
      sk_set_tbuf(socket, payload->data);
      err = sk_send_to(socket, payload->size, payload->addr, 162);
      if (err == 0) {
        /* Wait for transmission to complete */
        socket->tx_hook = snmp_tx_hook;
        return;
      }
      sk_set_tbuf(socket, NULL);
      if (err < 0) {
        log(L_ERR "%s: Error transmitting notification to %I: %s", snmp->p.name, payload->addr, socket->err);
      }
    }
    else {
      log(L_ERR "%s: Error creating socket", snmp->p.name);
    }

    rem_node(&payload->n);
    sl_free(snmp->payload_slab, payload);
  }

  if (snmp->terminating) {
    /* Terminate */
    proto_notify_state(&snmp->p, PS_DOWN);
  }
}

static void snmp_event_hook(void *data)
{
  struct snmp_proto *snmp = (struct snmp_proto *)data;
  snmp_flush_queue(snmp);
}

static struct proto *snmp_init(struct proto_config *c)
{
  return proto_new(c, sizeof(struct snmp_proto));
}

static int snmp_start(struct proto *proto)
{
  struct snmp_proto *snmp = (struct snmp_proto *)proto;

  snmp->payload_slab = sl_new(snmp->p.pool, sizeof(struct snmp_payload));
  snmp->socket = NULL;

  snmp->event = ev_new(snmp->p.pool);
  snmp->event->hook = snmp_event_hook;
  snmp->event->data = snmp;

  init_list(&snmp->payload_list);
  snmp->terminating = 0;

  snmp_instance = snmp;

  return PS_UP;
}

static int snmp_shutdown(struct proto *proto)
{
  struct snmp_proto *snmp = (struct snmp_proto *)proto;

  snmp_instance = NULL;

  if (EMPTY_LIST(snmp->payload_list)) {
    return PS_DOWN;
  }
  else {
    snmp->terminating = 1;
    return PS_STOP;
  }
}

void snmp_enqueue_notificationv(struct snmp_proto *snmp, const snmp_object_identifier *notification, va_list args)
{
  const struct snmp_config *cfg = (const struct snmp_config *)snmp->p.cf;
  const struct snmp_destination *dest;
  int need_schedule = 0;

  WALK_LIST(dest, cfg->destinations) {
    struct snmp_payload *payload = (struct snmp_payload *)sl_alloc(snmp->payload_slab);
    const char *community = (dest->community == NULL ? cfg->community : dest->community);
    payload->size = snmp_encode_notificationv(payload->data, sizeof(payload->data), community, notification, args);
    if (payload->size == 0) {
      log(L_WARN "%s: Notification exceeded limits", snmp->p.name);
      sl_free(snmp->payload_slab, payload);
    }
    else {
      payload->addr = dest->addr;

      if (EMPTY_LIST(snmp->payload_list))
        need_schedule = 1;

      add_tail(&snmp->payload_list, &payload->n);
    }
  }

  if (need_schedule)
    ev_schedule(snmp->event);
}

struct protocol proto_snmp = {
  .name =           "SNMP",
  .template =       "snmp%d",
  .init =           snmp_init,
  .start =          snmp_start,
  .shutdown =       snmp_shutdown,
};
