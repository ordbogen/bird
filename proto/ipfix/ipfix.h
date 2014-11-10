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
  u16 mtu;
  ipfix_protocol protocol;
  int interval;
  int template_interval;
};

struct ipfix_pending_packet {
  node n;
  int len;
  u8 data[];
};

struct ipfix_proto {
  struct proto p;
  struct ipfix_config *cfg;

  sock *sk;
  timer *counter_timer;
  timer *template_timer;

  u32 sequence_number;

  list pending_packets;
};

/* IPFIX protocol structures */

struct ipfix_message_header {
  u16 version_number;
  u16 length;
  u32 export_time;
  u32 sequence_number;
  u32 observation_domain_id;
};

struct ipfix_field_specifier {
  u16 information_element_id;
  u16 field_length;
};

struct ipfix_field_specifier_enterprise {
  u16 information_element_id;
  u16 field_length;
  u32 enterprise_number;
};

struct ipfix_set_header {
  u16 set_id;
  u16 length;
};

enum ipfix_set_id {
  IPFIX_TEMPLATE_SET = 2,
  IPFIX_OPTIONS_TEMPLATE_SET = 3,
  IPFIX_DATA_SET_BASE = 256
};

enum ipfix_data_set_index {
  IPFIX_DATA_SET_INDEX_FLOW_KEYS, /* Recommended in RFC 7011 */
  IPFIX_DATA_SET_INDEX_TYPE_INFO, /* Recommended in RFC 5610 */
  IPFIX_DATA_SET_INDEX_BIRD, /* BIRD specific */
};

enum ipfix_enterprise_number {
  IPFIX_ENTERPRISE_ORDBOGEN = 40446
};

typedef enum _ipfix_type {
  IPFIX_TYPE_INVALID = -1,
  IPFIX_TYPE_OCTET_ARRAY = 0,
  IPFIX_TYPE_UNSIGNED8 = 1,
  IPFIX_TYPE_UNSIGNED16 = 2,
  IPFIX_TYPE_UNSIGNED32 = 3,
  IPFIX_TYPE_UNSIGNED64 = 4,
  IPFIX_TYPE_SIGNED8 = 5,
  IPFIX_TYPE_SIGNED16 = 6,
  IPFIX_TYPE_SIGNED32 = 7,
  IPFIX_TYPE_SIGNED64 = 8,
  IPFIX_TYPE_FLOAT32 = 9,
  IPFIX_TYPE_FLOAT64 = 10,
  IPFIX_TYPE_BOOLEAN = 11,
  IPFIX_TYPE_MAC_ADDRESS = 12,
  IPFIX_TYPE_STRING = 13,
  IPFIX_TYPE_DATE_TIME_SECONDS = 14,
  IPFIX_TYPE_DATE_TIME_MILLISECONDS = 15,
  IPFIX_TYPE_DATE_TIME_MICROSECONDS = 16,
  IPFIX_TYPE_DATE_TIME_NANOSECONDS = 17,
  IPFIX_TYPE_IPV4_ADDRESS = 18,
  IPFIX_TYPE_IPV6_ADDRESS = 19,
  IPFIX_TYPE_BASIC_LIST = 20,
  IPFIX_TYPE_SUB_TEMPLATE_LIST = 21,
  IPFIX_TYPE_SUB_TEMPLATE_MULTI_LIST = 22
} ipfix_type;

typedef enum _ipfix_semantic {
  IPFIX_SEMANTIC_DEFAULT = 0,
  IPFIX_SEMANTIC_QUANTITY = 1,
  IPFIX_SEMANTIC_TOTAL_COUNTER = 2,
  IPFIX_SEMANTIC_DELTA_COUNTER = 3,
  IPFIX_SEMANTIC_IDENTIFIER = 4,
  IPFIX_SEMANTIC_FLAGS = 5,
  IPFIX_SEMANTIC_LIST = 6
} ipfix_semantic;

typedef enum _ipfix_unit {
  IPFIX_UNIT_NONE = 0,
  IPFIX_UNIT_BITS = 1,
  IPFIX_UNIT_OCTETS = 2,
  IPFIX_UNIT_PACKETS = 3,
  IPFIX_UNIT_FLOWS = 4,
  IPFIX_UNIT_SECONDS = 5,
  IPFIX_UNIT_MILLISECONDS = 6,
  IPFIX_UNIT_MICROSECONDS = 7,
  IPFIX_UNIT_NANOSECONDS = 8,
  IPFIX_UNIT_4_OCTET_WORD = 9,
  IPFIX_UNIT_MESSAGES = 10,
  IPFIX_UNIT_HOPS = 11,
  IPFIX_UNIT_ENTRIES = 12,
  IPFIX_UNIT_FRAMES = 13
} ipfix_unit;

typedef enum _ipfix_direction {
  IPFIX_INGRESS_FLOW = 0x00,
  IPFIX_EGRESS_FLOW = 0x01
} ipfix_direction;

typedef enum _ipfix_information_element {
  IPFIX_IE_FLOW_DIRECTION = 61, /* RFC 5102 */
  IPFIX_IE_TEMPLATE_ID = 145, /* RFC 5102 */
  IPFIX_IE_OBSERVATION_DOMAIN_ID = 149, /* RFC 5102 */
  IPFIX_IE_FLOW_START_SECONDS = 150, /* RFC 5102 */
  IPFIX_IE_FLOW_END_SECONDS = 151, /* RFC 5102 */
  IPFIX_IE_FLOW_KEY_INDICATOR = 173, /* RFC 5102 */
  IPFIX_IE_INFORMATION_ELEMENT_ID = 303, /* RFC 5477 */
  IPFIX_IE_INFORMATION_ELEMENT_DATA_TYPE = 339, /* RFC 5610 */
  IPFIX_IE_INFORMATION_ELEMENT_DESCRIPTION = 340, /* RFC 5610 */
  IPFIX_IE_INFORMATION_ELEMENT_NAME = 341, /* RFC 5610 */
  IPFIX_IE_INFORMATION_ELEMENT_RANGE_BEGIN = 342, /* RFC 5610 */
  IPFIX_IE_INFORMATION_ELEMENT_RANGE_END = 343, /* RFC 5610 */
  IPFIX_IE_INFORMATION_ELEMENT_SEMANTICS = 344, /* RFC 5610 */
  IPFIX_IE_INFORMATION_ELEMENT_UNITS = 345, /* RFC 5610 */
  IPFIX_IE_PRIVATE_ENTERPRISE_NUMBER = 346 /* RFC 5610 */
} ipfix_informtion_element;

typedef enum _ipfix_bird_information_element {
  IPFIX_IE_BIRD_NAME = 1,
  IPFIX_IE_BIRD_ROUTES = 2,
  IPFIX_IE_BIRD_FILTERED_ROUTES = 3,
  IPFIX_IE_BIRD_PREFERRED_ROUTES = 4,

  IPFIX_IE_BIRD_UPDATES = 5,
  IPFIX_IE_BIRD_INVALID_UPDATES = 6,
  IPFIX_IE_BIRD_FILTERED_UPDATES = 7,
  IPFIX_IE_BIRD_IGNORED_UPDATES = 8,
  IPFIX_IE_BIRD_ACCEPTED_UPDATES = 9,

  IPFIX_IE_BIRD_WITHDRAWS = 10,
  IPFIX_IE_BIRD_INVALID_WITHDRAWS = 11,
  IPFIX_IE_BIRD_IGNORED_WITHDRAWS = 12,
  IPFIX_IE_BIRD_ACCEPTED_WITHDRAWS = 13
} ipfix_bird_information_element;

struct ipfix_template_record_header {
  u16 template_id;
  u16 field_count;
};

struct ipfix_option_template_record_header {
  u16 template_id;
  u16 field_count;
  u16 scope_field_count;
};

/* Private API */

int ipfix_fill_template(u8 *ptr, u8 *end, u32 sequence_number, int *ptemplate_offset, int *poptions_template_offset, int *pflow_id_offset, int *ptype_info_offset);
int ipfix_fill_counters(u8 *ptr, u8 *end, u32 sequence_number, int *pproto_offset);

#endif // _BIRD_IPFIX_H_
