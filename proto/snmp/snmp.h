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

enum snmp_version
{
  SNMP_VERSION_DEFAULT,
  SNMP_VERSION_2C,
  SNMP_VERSION_3
};

struct snmp_params
{
  enum snmp_version version;
  /* SNMPv2c parameters */
  char *community;
  /* SNMPv3 USM parameters */
  u8 engine_id[12];
  int has_engine_id;
  int engine_id_length;
  char *username;
  char *password;
  u8 key[12];
  int has_key;
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
    const struct snmp_params *params,
    const snmp_object_identifier *notification,
    va_list args);

#endif /* _BIRD_SNMP_H_ */
