/*
 *  BIRD -- Simple Network Management Protocol (SNMP)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SNMP_H_
#define _BIRD_SNMP_H_

#include "nest/bird.h"

#include "nest/protocol.h"
#include "nest/snmp.h"
#include "lib/event.h"
#include "lib/socket.h"

struct snmp_params
{
  char *community;
};

struct snmp_destination
{
  node n;
  ip_addr addr;
  struct snmp_params params;
};

struct snmp_config
{
  struct proto_config c;
  list destinations;
  struct snmp_params def_params;
};

struct snmp_payload
{
  node n;
  ip_addr addr;
#ifdef IPV6
  unsigned char data[1232]; /* See RFC 2460, p. 25 */
#else /* IPV6 */
  unsigned char data[512]; /* See RFC 791, p. 13 */
#endif /* IPV6 */
  unsigned int size;
};

struct snmp_proto
{
  struct proto p;
  slab *payload_slab;
  sock *socket;
  event *event;
  list payload_list;
  int terminating;
};

extern struct snmp_proto *snmp_instance;

void snmp_enqueue_notificationv(
    struct snmp_proto *proto,
    const snmp_object_identifier *notification,
    va_list args);

unsigned int snmp_encode_notificationv(
    void *buffer,
    unsigned int buffer_size,
    const char *community,
    const snmp_object_identifier *notification,
    va_list args);

#endif /* _BIRD_SNMP_H_ */
