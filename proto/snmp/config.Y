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

static struct snmp_params *this_params;

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
  this_params = &snmp_cf->def_params;
};

snmp_destination_start: DESTINATION ipa
{
  struct snmp_destination *destination = cfg_allocz(sizeof(struct snmp_destination));
  destination->addr = $2;
  add_tail(&SNMP_CFG->destinations, &destination->n);

  this_params = &destination->params;
};

snmp_config_item:
   COMMUNITY text { this_params->community = $2; }
 ;

snmp_destination_opts:
   /* empty */
 | snmp_destination_opts snmp_config_item ';'
 ;

snmp_destination:
   snmp_destination_start '{' snmp_destination_opts '}' { this_params = &SNMP_CFG->def_params; }
 | snmp_destination_start { this_params = &SNMP_CFG->def_params; }
 ;

snmp_proto_item:
   proto_item
 | snmp_config_item
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

  if (SNMP_CFG->def_params.community == NULL) {
    struct snmp_destination *dest;
    WALK_LIST(dest, SNMP_CFG->destinations) {
      if (dest->params.community == NULL)
        cf_error("Missing community");
    }
  }
};

CF_CODE

CF_END
