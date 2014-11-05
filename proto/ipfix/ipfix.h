/*
 *  BIRD -- IP Flow Information Export (IPFIX)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL
 */

#ifndef _BIRD_IPFIX_H_
#define _BIRD_IPFIX_H_

typedef enum _ipfix_protocol {
  IPFIX_PROTO_SCTP,
  IPFIX_PROTO_TCP,
  IPFIX_PROTO_UDP
} ipfix_protocol;

struct ipfix_config {
  struct proto_config c;
  ip_addr source;
  ip_addr dest;
  u16 port;
  ipfix_protocol protocol;
  int interval;
  int template_interval;
};

struct ipfix_proto {
  struct proto p;
  struct ipfix_config *cfg;

  int template_sent;
  sock *sk;
  timer *counter_timer;
  timer *template_timer;

  u32 sequence_number;
};

#endif // _BIRD_IPFIX_H_
