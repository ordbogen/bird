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

static void snmp_add_destination(list *destinations, ip_addr addr, char *community)
{
  struct snmp_destination *destination = (struct snmp_destination *)cfg_allocz(sizeof(struct snmp_destination));
  destination->addr = addr;
  destination->community = (community == NULL ? NULL : cfg_strdup(community));
  add_tail(destinations, &destination->n);
}

CF_DECLS

CF_KEYWORDS(SNMP, DESTINATION, COMMUNITY)

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

snmp_community: text
{
  SNMP_CFG->community = $1;
};

snmp_destination_simple: ipa
{
  snmp_add_destination(&SNMP_CFG->destinations, $1, NULL);
};

snmp_destination_advanced: ipa COMMUNITY text
{
  snmp_add_destination(&SNMP_CFG->destinations, $1, $3);
};

snmp_destination:
   snmp_destination_simple
 | snmp_destination_advanced
 ;

snmp_proto_item:
   proto_item
 | DESTINATION snmp_destination
 | COMMUNITY snmp_community
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
    struct snmp_destination dest;
    WALK_LIST(dest, SNMP_CFG->destinations) {
      if (dest->community == NULL)
        cf_error("Missing community");
    }
  }
};

CF_CODE

CF_END
