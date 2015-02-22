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
void snmp_encode_password(struct snmp_params *params);
int snmp_parse_key_or_engine_id(const char *string, u8 *buffer);

static struct snmp_params *this_params;

CF_DECLS

CF_KEYWORDS(SNMP, ADDRESS, DESTINATION, VERSION, V2C, V3)
CF_KEYWORDS(COMMUNITY)
CF_KEYWORDS(ENGINE, ID, USERNAME, PASSWORD, KEY)

CF_GRAMMAR

CF_ADDTO(proto, snmp_proto)

snmp_proto_start: proto_start SNMP
{
  this_proto = proto_config_new(&proto_snmp, sizeof(struct snmp_config), $1);
  init_list(&SNMP_CFG->destinations);

  if (snmp_cf)
    cf_error("Only one SNMP instance allowed");
  snmp_cf = SNMP_CFG;
  snmp_cf->def_params.version = SNMP_VERSION_2C;
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
   VERSION V2C { this_params->community = SNMP_VERSION_2C; }
 | VERSION V3 { this_params->community = SNMP_VERSION_3; }
 | COMMUNITY text { this_params->community = $2; }
 | ENGINE ID text { if (snmp_parse_key_or_engine_id($3, this_params->engine_id)) this_params->has_engine_id = 1; else cf_error("Invalid engine id"); }
 | USERNAME text { this_params->username = $2; }
 | PASSWORD text { this_params->password = $2; }
 | KEY text { if (snmp_parse_key_or_engine_id($2, this_params->key)) this_params->has_key = 1; else cf_error("Invalid key"); }
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

  struct snmp_destination *dest;
  WALK_LIST(dest, SNMP_CFG->destinations) {
    /* Copy from defaults */
    if (dest->params.version == SNMP_VERSION_DEFAULT)
      dest->params.version = SNMP_CFG->def_params.version;

    if (dest->params.community == NULL)
      dest->params.community = SNMP_CFG->def_params.community;

    if (!dest->params.has_engine_id && SNMP_CFG->def_params.engine_id) {
      memcpy(&dest->params.engine_id, &SNMP_CFG->def_params.engine_id, 12);
      dest->params.has_engine_id = 1;
    }

    if (dest->params.username == NULL)
      dest->params.username = SNMP_CFG->def_params.username;

    if (dest->params.password == NULL)
      dest->params.password = SNMP_CFG->def_params.password;

    if (!dest->params.has_key && SNMP_CFG->def_params.has_key) {
      memcpy(dest->params.key, SNMP_CFG->def_params.key, 12);
      dest->params.has_key = 1;
    }

    /* Validate */
    if (dest->params.version == SNMP_VERSION_2C) {
      if (dest->params.community == NULL)
        cf_error("Missing community");
    }
    else /*if (dest->params.version == SNMP_VERSION_3)*/ {
      if (dest->params.username == NULL)
        cf_error("Missing username");

      if (dest->params.password != NULL) {
        snmp_encode_password(&dest->params);
      }
    }
  }
};

CF_CODE

CF_END
