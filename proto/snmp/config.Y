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
int snmp_parse_hex(const char *string, int size, u8 *buffer);

static struct snmp_params *this_params;

CF_DECLS

CF_KEYWORDS(SNMP, ADDRESS, DESTINATION, VERSION, V2C, V3)
CF_KEYWORDS(COMMUNITY)
CF_KEYWORDS(CONTEXT, AUTH, ENGINE, ID, NAME, USERNAME, PASSWORD, KEY, MD5)

CF_GRAMMAR

CF_ADDTO(proto, snmp_proto)

snmp_proto_start: proto_start SNMP
{
  static const u8 default_engine_id[] = {
    0x80, 0x00, 0x63, 0xFB, /* RFC 3411 compliant, enterprise 25595 (CZ.NIC, z.s.p.o) */
    0x04, /* text engine id */
    'B', 'I', 'R', 'D'
  };

  this_proto = proto_config_new(&proto_snmp, sizeof(struct snmp_config), $1);
  init_list(&SNMP_CFG->destinations);

  if (snmp_cf)
    cf_error("Only one SNMP instance allowed");
  snmp_cf = SNMP_CFG;
  snmp_cf->def_params.version = SNMP_VERSION_2C;
  snmp_cf->def_params.community = "public";

  memcpy(snmp_cf->def_params.context_engine_id, default_engine_id, sizeof(default_engine_id));
  snmp_cf->def_params.context_engine_id_length = sizeof(default_engine_id);

  memcpy(snmp_cf->def_params.auth_engine_id, default_engine_id, sizeof(default_engine_id));
  snmp_cf->def_params.auth_engine_id_length = sizeof(default_engine_id);

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
   VERSION V2C { this_params->version = SNMP_VERSION_2C; }
 | VERSION V3 { this_params->version = SNMP_VERSION_3; }
 | COMMUNITY text { this_params->community = $2; }
 | CONTEXT ENGINE ID text { if ((this_params->context_engine_id_length = snmp_parse_hex($4, 32, this_params->context_engine_id)) == 0) cf_error("Invalid engine id"); }
 | CONTEXT NAME text { this_params->context_name = $3; }
 | AUTH ENGINE ID text { if ((this_params->auth_engine_id_length = snmp_parse_hex($4, 32, this_params->auth_engine_id)) == 0) cf_error("Invalid engine id"); }
 | USERNAME text { this_params->username = $2; }
 | PASSWORD MD5 text { this_params->password = $3; }
 | KEY MD5 text { if ((this_params->key_length = snmp_parse_hex($3, 16, this_params->key)) != 16) cf_error("Invalid key"); }
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

    if (dest->params.context_engine_id_length == 0) {
      memcpy(dest->params.context_engine_id, SNMP_CFG->def_params.context_engine_id, SNMP_CFG->def_params.context_engine_id_length);
      dest->params.context_engine_id_length = SNMP_CFG->def_params.context_engine_id_length;
    }

    if (dest->params.context_name == NULL)
      dest->params.context_name = SNMP_CFG->def_params.context_name;

    if (dest->params.username == NULL)
      dest->params.username = SNMP_CFG->def_params.username;

    if (dest->params.password == NULL)
      dest->params.password = SNMP_CFG->def_params.password;

    if (dest->params.auth_engine_id_length == 0) {
      memcpy(dest->params.auth_engine_id, SNMP_CFG->def_params.auth_engine_id, SNMP_CFG->def_params.auth_engine_id_length);
      dest->params.auth_engine_id_length = SNMP_CFG->def_params.auth_engine_id_length;
    }

    /* Validate */
    if (dest->params.version == SNMP_VERSION_2C) {
      if (dest->params.community == NULL)
        cf_error("Missing community");
    }
    else /*if (dest->params.version == SNMP_VERSION_3)*/ {
      if (dest->params.password != NULL) {
        snmp_encode_password(&dest->params);
      }
    }
  }
};

CF_CODE

CF_END
