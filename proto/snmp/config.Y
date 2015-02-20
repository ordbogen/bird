/*
 *  BIRD -- Simple Network Management Protocol (SNMP)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/snmp/snmp.h"
#include "lib/lists.h"

CF_DEFINES

#define SNMP_CFG ((struct snmp_config *)this_proto)

extern struct snmp_config *snmp_cf;

static struct snmp_destination *this_destination = NULL;

CF_DECLS

CF_KEYWORDS(SNMP, ADDRESS, DESTINATION, COMMUNITY)

CF_GRAMMAR

CF_ADDTO(proto, snmp_proto)

snmp_proto_start: proto_start SNMP
{
  this_proto = proto_config_new(&proto_snmp, sizeof(struct snmp_config), $1);
  init_list(&SNMP_CFG->destinations);

  if (snmp_cf)
    cf_error("Only one SNMP instance allowed");
  snmp_cf = SNMP_CFG;
};

snmp_destination_start: DESTINATION ipa
{
  this_destination = cfg_allocz(sizeof(struct snmp_destination));
  this_destination->addr = $2;
  add_tail(&SNMP_CFG->destinations, &this_destination->n);
};

snmp_destination_item:
   COMMUNITY text { this_destination->community = $2; }
 ;

snmp_destination_opts:
   /* empty */
 | snmp_destination_opts snmp_destination_item ';'
 ;

snmp_destination:
   snmp_destination_start '{' snmp_destination_opts '}'
 | snmp_destination_start
 ;

snmp_proto_item:
   proto_item
 | COMMUNITY text { SNMP_CFG->community = $2; }
 | snmp_destination
 ;

snmp_proto_opts:
   /* empty */
 | snmp_proto_opts snmp_proto_item ';'
 ;

snmp_proto: snmp_proto_start proto_name '{' snmp_proto_opts '}'
{
  if (EMPTY_LIST(SNMP_CFG->destinations))
    cf_error("Missing destinations");

  if (SNMP_CFG->community == NULL) {
    struct snmp_destination *dest;
    WALK_LIST(dest, SNMP_CFG->destinations) {
      if (dest->community == NULL)
        cf_error("Missing community");
    }
  }
};

CF_CODE

CF_END
