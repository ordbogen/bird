/*
 *  BIRD -- IP Flow Information Export (IPFIX)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL
 */

CF_HDR

#include "proto/ipfix/ipfix.h"

CF_DEFINES

#define IPFIX_CFG ((struct ipfix_config *)this_proto)

CF_DECLS

CF_KEYWORDS(IPFIX, PROTOCOL, SOURCE, DESTINATION, PORT, TEMPLATE, INTERVAL, TCP, UDP, SCTP, MTU, REDUCED, SYSTEM, OBSERVATION, DOMAIN, ID, DATA)

%type <i> ipfix_port;
%type <i> ipfix_proto;
%type <i> ipfix_mtu;
%type <i> ipfix_observation_domain_id;

CF_GRAMMAR

CF_ADDTO(proto, ipfix_proto)

ipfix_proto_start: proto_start IPFIX
{
  this_proto = proto_config_new(&proto_ipfix, sizeof(struct ipfix_config), $1);
  IPFIX_CFG->data_interval = 60;
  IPFIX_CFG->template_interval = 600;
  IPFIX_CFG->protocol = IPFIX_PROTO_UDP;
  IPFIX_CFG->system_template = 1;
};

ipfix_port:
   /* empty */ { $$ = 4739; }
 | PORT expr { $$ = $2; }
 ;

ipfix_destination: ipa ipfix_port
{
  if (ipa_nonzero(IPFIX_CFG->dest))
    cf_error("Only one destination per IPFIX instance is allowed");

  IPFIX_CFG->dest = $1;
  IPFIX_CFG->port = $2;

  if (IPFIX_CFG->port <= 0 || IPFIX_CFG->port > 65535)
    cf_error("Invalid port number");
};

ipfix_source: ipa
{
  IPFIX_CFG->source = $1;
};

ipfix_proto:
   SCTP { $$ = IPFIX_PROTO_SCTP; }
 | TCP { $$ = IPFIX_PROTO_TCP; }
 | UDP { $$ = IPFIX_PROTO_UDP; }
 ;

ipfix_protocol: ipfix_proto
{
  IPFIX_CFG->protocol = $1;
};

ipfix_interval: expr
{
  IPFIX_CFG->data_interval = $1;
  if (IPFIX_CFG->data_interval <= 0 )
    cf_error("Invalid interval");
};

ipfix_template_interval: expr
{
  IPFIX_CFG->template_interval = $1;
  if (IPFIX_CFG->template_interval <= 0)
    cf_error("Invalid template interval");
};

ipfix_mtu: expr
{
  IPFIX_CFG->mtu = $1;
};

ipfix_reduced_template: bool
{
  IPFIX_CFG->reduced_template = $1;
};

ipfix_system_template: bool
{
  IPFIX_CFG->system_template = $1;
};

ipfix_observation_domain_id: expr
{
  IPFIX_CFG->observation_domain_id = $1;
};

ipfix_proto_item:
   proto_item
 | DESTINATION ipfix_destination
 | SOURCE ipfix_source
 | PROTOCOL ipfix_protocol
 | DATA INTERVAL ipfix_interval
 | TEMPLATE INTERVAL ipfix_template_interval
 | MTU ipfix_mtu
 | REDUCED TEMPLATE ipfix_reduced_template
 | SYSTEM TEMPLATE ipfix_system_template
 | OBSERVATION DOMAIN ID ipfix_observation_domain_id
 ;

ipfix_proto_opts:
   /* empty */
 | ipfix_proto_opts ipfix_proto_item ';'
 ;

ipfix_proto: ipfix_proto_start proto_name '{' ipfix_proto_opts '}'
{
  if (IPFIX_CFG->protocol == IPFIX_PROTO_SCTP)
    cf_error("SCTP not supported yet");

  if (ipa_zero(IPFIX_CFG->dest))
    cf_error("Missing destination");

  if (IPFIX_CFG->mtu == 0) {
    if (IPFIX_CFG->protocol == IPFIX_PROTO_TCP)
      IPFIX_CFG->mtu = 65535;
    else
      IPFIX_CFG->mtu = 512;
  }
};

CF_CODE

CF_END
