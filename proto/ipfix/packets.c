/*
 *  BIRD -- IP Flow Information Export (IPFIX)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL
 */

#include "nest/bird.h"
#include "nest/protocol.h"
#include "lib/socket.h"
#include "lib/timer.h"

#include "ipfix.h"

#include <arpa/inet.h>

static inline u8 *ipfix_add_octet_string(u8 *ptr, u8 *end, const void *string, int length)
{
  if (ptr == NULL)
    return NULL;

  if (length < 256) {
    if (ptr + length + 1 > end)
      return NULL;
    *(u8 *)ptr = length;
    ++ptr;
  }
  else {
    if (ptr + length + 3 > end)
      return NULL;

    *(u8 *)ptr = 255;
    ++ptr;

    *(u16 *)ptr = htons(length);
    ptr += 2;
  }

  memcpy(ptr, string, length);

  return ptr + length;
}  

static inline u8 *ipfix_add_string(u8 *ptr, u8 *end, const char *string)
{
  return ipfix_add_octet_string(ptr, end, string, strlen(string));
}

static u8 *ipfix_add_record(u8 *ptr, u8 *end, ...)
{
  va_list args;
  ipfix_type type;

  if (ptr == NULL)
    return NULL;

  va_start(args, end);

  while (ptr != NULL && ptr != end && (type = va_arg(args, ipfix_type)) != IPFIX_TYPE_INVALID) {
    switch (type) {
      case IPFIX_TYPE_OCTET_ARRAY:
        ptr = ipfix_add_octet_string(ptr, end, va_arg(args, const void *), va_arg(args, int));
        break;

      case IPFIX_TYPE_UNSIGNED8:
        *(u8 *)ptr = va_arg(args, unsigned int);
        ++ptr;
        break;

      case IPFIX_TYPE_UNSIGNED16:
        if (ptr + 2 > end)
          ptr = NULL;
        else {
          *(u16 *)ptr = htons(va_arg(args, unsigned int));
          ptr += 2;
        }
        break;

      case IPFIX_TYPE_UNSIGNED32:
        if (ptr + 4 > end)
          ptr = NULL;
        else {
          *(u32 *)ptr = htonl(va_arg(args, unsigned int));
          ptr += 4;
        }
        break;

      case IPFIX_TYPE_UNSIGNED64:
        if (ptr + 8 > end)
          ptr = NULL;
        else {
          // TODO
          ptr += 8;
        }
        break;

      case IPFIX_TYPE_SIGNED8:
        *(u8 *)ptr = va_arg(args, int);
        ++ptr;
        break;

      case IPFIX_TYPE_SIGNED16:
        if (ptr + 2 > end)
          ptr = NULL;
        else {
          *(u16 *)ptr = htons(va_arg(args, int));
          ptr += 2;
        }
        break;

      case IPFIX_TYPE_SIGNED32:
        if (ptr + 4 > end)
          ptr = NULL;
        else {
          *(u32 *)ptr = htonl(va_arg(args, int));
          ptr += 4;
        }
        break;

      case IPFIX_TYPE_SIGNED64:
        if (ptr + 8 > end)
          ptr = NULL;
        else {
          // TODO
          ptr += 8;
        }
        break;


      case IPFIX_TYPE_FLOAT32:
        if (ptr + 4 > end)
          ptr = NULL;
        else {
          // TODO
          ptr += 4;
        }
        break;

      case IPFIX_TYPE_FLOAT64:
        if (ptr + 8 > end)
          ptr = NULL;
        else {
          // TODO
          ptr += 8;
        }
        break;

      case IPFIX_TYPE_BOOLEAN:
        *(u8 *)ptr = (va_arg(args, int) ? 1 : 0);
        ++ptr;
        break;

      case IPFIX_TYPE_MAC_ADDRESS:
        // TODO
        break;

      case IPFIX_TYPE_STRING:
        ptr = ipfix_add_string(ptr, end, va_arg(args, const char *));
        break;

      case IPFIX_TYPE_DATE_TIME_SECONDS:
        if (ptr + 4 > end)
          ptr = NULL;
        else {
          *(u32 *)ptr = htonl(va_arg(args, unsigned int));
          ptr += 4;
        }
        break;

      case IPFIX_TYPE_DATE_TIME_MILLISECONDS:
      case IPFIX_TYPE_DATE_TIME_MICROSECONDS:
      case IPFIX_TYPE_DATE_TIME_NANOSECONDS:
        if (ptr + 8 > end)
          return NULL;
        else {
          // TODO
          ptr += 8;
        }
        break;

      case IPFIX_TYPE_IPV4_ADDRESS:
        if (ptr + 4 > end)
          return NULL;
        else {
          // TODO
          ptr += 4;
        }
        break;

      case IPFIX_TYPE_IPV6_ADDRESS:
        if (ptr + 16 > end)
          return NULL;
        else {
          // TODO
          ptr += 16;
        }
        break;

      case IPFIX_TYPE_BASIC_LIST:
        break;

      case IPFIX_TYPE_SUB_TEMPLATE_LIST:
        break;

      case IPFIX_TYPE_SUB_TEMPLATE_MULTI_LIST:
        break;

      case IPFIX_TYPE_INVALID:
        break;
    }
  }

  va_end(args);

  return ptr;
}


static inline u8 *ipfix_prepare_header(u8 *ptr, u32 sequence_number)
{
  struct ipfix_message_header *header = (struct ipfix_message_header *)ptr;
  header->version_number = htons(10);
  /* header->length = 0; */
  header->export_time = htonl(now_real);
  header->sequence_number = htonl(sequence_number);
  header->observation_domain_id = 0;

  return ptr + sizeof(struct ipfix_message_header);
}

static inline void ipfix_finalize_header(u8 *ptr, u8 *end_of_pkt)
{
  struct ipfix_message_header *header;

  if (ptr == NULL || end_of_pkt == NULL)
    return;

  header = (struct ipfix_message_header *)ptr;
  header->length = htons(end_of_pkt - ptr);
}

static inline u8 *ipfix_prepare_set(u8 *ptr, u8 *end, u16 set_id)
{
  struct ipfix_set_header *header;

  if (ptr == NULL || ptr + sizeof(struct ipfix_set_header) > end)
    return NULL;

  header = (struct ipfix_set_header *)ptr;
  header->set_id = htons(set_id);
  /* header->length = 0 */
  return ptr + sizeof(struct ipfix_set_header);
}

static inline u8 *ipfix_finalize_set(u8 *ptr, u8 *end_of_set)
{
  struct ipfix_set_header *header;

  if (ptr == NULL || end_of_set == NULL)
    return NULL;

  while (((uintptr_t)end_of_set & 0x3) != 0) {
    *end_of_set++ = 0;
  }

  header = (struct ipfix_set_header *)ptr;
  header->length = htons(end_of_set - ptr);

  return end_of_set;
}

static inline u8 *ipfix_add_template_record(
    u8 *ptr,
    u8 *end,
    u16 template_id,
    u16 field_count)
{
  struct ipfix_template_record_header *header;

  if (ptr == NULL || ptr + sizeof(struct ipfix_template_record_header) > end)
    return NULL;

  header = (struct ipfix_template_record_header *)ptr;
  header->template_id = htons(template_id);
  header->field_count = htons(field_count);
  return ptr + sizeof(*header);
}

static inline u8 *ipfix_add_options_template_record(
    u8 *ptr,
    u8 *end,
    u16 template_id,
    u16 field_count,
    u16 scope_field_count)
{
  struct ipfix_option_template_record_header *header;

  if (ptr == NULL || ptr + sizeof(struct ipfix_option_template_record_header) > end)
    return NULL;
 
  header = (struct ipfix_option_template_record_header *)ptr;
  header->template_id = htons(template_id);
  header->field_count = htons(field_count);
  header->scope_field_count = htons(scope_field_count);
  return ptr + sizeof(*header);
}

static inline u8 *ipfix_add_field_specifier(
    u8 *ptr,
    u8 *end,
    u16 information_element_id,
    u16 field_length,
    u32 enterprise_number)
{
  if (enterprise_number == 0) {
    struct ipfix_field_specifier *f = (struct ipfix_field_specifier *)ptr;
    f->information_element_id = htons(information_element_id);
    f->field_length = htons(field_length);
    return ptr + sizeof(*f);
  }
  else {
    struct ipfix_field_specifier_enterprise *f = (struct ipfix_field_specifier_enterprise *)ptr;
    f->information_element_id = htons(information_element_id | 0x8000);
    f->field_length = htons(field_length);
    f->enterprise_number = htonl(enterprise_number);
    return ptr + sizeof(*f);
  }
}

static inline u8 *ipfix_add_template_set(u8 *ptr, u8 *end, int *ptemplate_offset)
{
  static const struct
  {
    u16 id;
    u16 field_count;
    struct
    {
      u16 id;
      u16 length;
      u16 enterprise_id;
    } fields[16];
  } templates[] = {
    {
      IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_BIRD,
      14,
      {
        {IPFIX_IE_BIRD_NAME, 65535, IPFIX_ENTERPRISE_ORDBOGEN}, /* Flow key */
        {IPFIX_IE_FLOW_DIRECTION, 1, 0}, /* Flow key */

        {IPFIX_IE_BIRD_ROUTES, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_FILTERED_ROUTES, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_PREFERRED_ROUTES, 4, IPFIX_ENTERPRISE_ORDBOGEN},

        {IPFIX_IE_BIRD_UPDATES, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_INVALID_UPDATES, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_FILTERED_UPDATES, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_IGNORED_UPDATES, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_ACCEPTED_UPDATES, 4, IPFIX_ENTERPRISE_ORDBOGEN},

        {IPFIX_IE_BIRD_WITHDRAWS, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_INVALID_WITHDRAWS, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_IGNORED_WITHDRAWS, 4, IPFIX_ENTERPRISE_ORDBOGEN},
        {IPFIX_IE_BIRD_ACCEPTED_WITHDRAWS, 4, IPFIX_ENTERPRISE_ORDBOGEN}
      }
    }
  };
  u8 *set_ptr;
  unsigned int i;

  set_ptr = ptr;
  ptr = ipfix_prepare_set(set_ptr, end, IPFIX_TEMPLATE_SET);

  for (i = *ptemplate_offset; i != sizeof(templates) / sizeof(templates[0]); ++i) {
    u8 *template_ptr = ptr;
    unsigned int j;

    ptr = ipfix_add_template_record(ptr, end, templates[i].id, templates[i].field_count);

    for (j = 0; j != templates[i].field_count; ++j) {
      ptr = ipfix_add_field_specifier(ptr, end,
          templates[i].fields[j].id,
          templates[i].fields[j].length,
          templates[i].fields[j].enterprise_id);
    }

    if (ptr == NULL) {
      ptr = template_ptr;
      break;
    }
  }
  if (i == sizeof(templates) / sizeof(templates[0]))
    *ptemplate_offset = -1;
  else
    *ptemplate_offset = i;

  ptr = ipfix_finalize_set(set_ptr, ptr);

  return ptr;
}

static inline u8 *ipfix_add_options_template_set(u8 *ptr, u8 *end, int *poptions_template_offset)
{
  static const struct
  {
    u16 id;
    u16 field_count;
    u16 scope_field_count;
    struct {
      u16 id;
      u16 length;
      u32 enterprise_id;
    } records[11];
  } templates[] = {
    {
      IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_FLOW_KEYS, 2, 1,
      {
        {IPFIX_IE_TEMPLATE_ID, 2, 0}, /* Scope */
        {IPFIX_IE_FLOW_KEY_INDICATOR, 4, 0} /* Really Unsigned64 */
      }     
    },
    {
      IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_TYPE_INFO, 9, 2,
      {
        {IPFIX_IE_INFORMATION_ELEMENT_ID, 2, 0}, /* Scope */
        {IPFIX_IE_PRIVATE_ENTERPRISE_NUMBER, 4, 0}, /* Scope */
        {IPFIX_IE_INFORMATION_ELEMENT_DATA_TYPE, 1, 0},
        {IPFIX_IE_INFORMATION_ELEMENT_SEMANTICS, 1, 0},
        {IPFIX_IE_INFORMATION_ELEMENT_UNITS, 1, 0},
        {IPFIX_IE_INFORMATION_ELEMENT_RANGE_BEGIN, 4, 0}, // Really Unsigned64 */
        {IPFIX_IE_INFORMATION_ELEMENT_RANGE_END, 4, 0}, /* Really Unsigned64 */
        {IPFIX_IE_INFORMATION_ELEMENT_NAME, 65535, 0},
        {IPFIX_IE_INFORMATION_ELEMENT_DESCRIPTION, 65535, 0}
      }
    }
  };
  u8 *set_ptr;
  unsigned int i;
 
  set_ptr = ptr;
  ptr = ipfix_prepare_set(set_ptr, end, IPFIX_OPTIONS_TEMPLATE_SET);

  for (i = *poptions_template_offset; i != sizeof(templates) / sizeof(templates[0]); ++i) {
    u8 *template_ptr = ptr;
    unsigned int j;

    ptr = ipfix_add_options_template_record(
        ptr,
        end,
        templates[i].id,
        templates[i].field_count,
        templates[i].scope_field_count);

    for (j = 0; j != templates[i].field_count; ++j) {
      ptr = ipfix_add_field_specifier(
          ptr,
          end,
          templates[i].records[j].id,
          templates[i].records[j].length,
          templates[i].records[j].enterprise_id);
    }

    if (ptr == NULL) {
      ptr = template_ptr;
      break;
    }
  }
  if (i == sizeof(templates) / sizeof(templates[0]))
    *poptions_template_offset = -1;
  else
    *poptions_template_offset = i;

  ptr = ipfix_finalize_set(set_ptr, ptr);

  return ptr;
}

static inline u8 *ipfix_add_type_info_data_set(u8 *ptr, u8 *end, int *ptype_info_offset)
{
  static const struct {
    u16 elementId;
    u32 privateEnterpriseNumber;
    ipfix_type dataType;
    ipfix_semantic semantic;
    ipfix_unit units;
    u32 rangeBegin;
    u32 rangeEnd;
    const char *name;
    const char *description;
  } type_info[] = {
    {
      IPFIX_IE_BIRD_NAME,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_STRING,
      IPFIX_SEMANTIC_DEFAULT,
      IPFIX_UNIT_NONE,
      0,
      0,
      "birdName",
      "Name of BIRD protocol"
    },
    {
      IPFIX_IE_BIRD_ROUTES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_QUANTITY,
      IPFIX_UNIT_NONE,
      0,
      0xFFFFFFFF,
      "birdRoutes",
      "Number of routes"
    },
    {
      IPFIX_IE_BIRD_FILTERED_ROUTES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_QUANTITY,
      IPFIX_UNIT_NONE,
      0,
      0xFFFFFFFF,
      "birdFilteredRoutes",
      "Number of filtered routes"
    },
    {
      IPFIX_IE_BIRD_PREFERRED_ROUTES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_QUANTITY,
      IPFIX_UNIT_NONE,
      0,
      0xFFFFFFFF,
      "birdPreferredRoutes",
      "Number of preferred routes"
    },
    {
      IPFIX_IE_BIRD_UPDATES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdUpdatesTotalCount",
      "Number of updates"
    },
    {
      IPFIX_IE_BIRD_INVALID_UPDATES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdInvalidUpdatesTotalCount",
      "Number of invalid updates"
    },
    {
      IPFIX_IE_BIRD_FILTERED_UPDATES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdFilteredUpdatesTotalCount",
      "Number of filtered updates"
    },
    {
      IPFIX_IE_BIRD_IGNORED_UPDATES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdIgnoredUpdatesTotalCount",
      "Number of ignored updates"
    },
    {
      IPFIX_IE_BIRD_ACCEPTED_UPDATES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdAcceptedUpdatesTotalCount",
      "Number of accepted updates"
    },
    {
      IPFIX_IE_BIRD_WITHDRAWS,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdWithdrawsTotalCount",
      "Number of withdrawals"
    },
    {
      IPFIX_IE_BIRD_INVALID_WITHDRAWS,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdInvalidWithdrawsTotalCount",
      "Number of invalid withdrawals"
    },
    {
      IPFIX_IE_BIRD_IGNORED_WITHDRAWS,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdIgnoredWithdrawsTotalCount",
      "Number of ignored withdrawals"
    },
    {
      IPFIX_IE_BIRD_ACCEPTED_WITHDRAWS,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_MESSAGES,
      0,
      0xFFFFFFFF,
      "birdAcceptedWithdrawsTotalCount",
      "Number of accepted withdrawals"
    }
  };
  u8 *set_ptr;
  unsigned int i;

  set_ptr = ptr;
  ptr = ipfix_prepare_set(set_ptr, end, IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_TYPE_INFO);

  for (i = *ptype_info_offset; i != sizeof(type_info) / sizeof(type_info[0]); ++i) {
    u8 *new_ptr = ipfix_add_record(ptr, end,
        IPFIX_TYPE_UNSIGNED16, type_info[i].elementId,
        IPFIX_TYPE_UNSIGNED32, type_info[i].privateEnterpriseNumber,
        IPFIX_TYPE_UNSIGNED8, type_info[i].dataType,
        IPFIX_TYPE_UNSIGNED8, type_info[i].semantic,
        IPFIX_TYPE_UNSIGNED8, type_info[i].units,
        IPFIX_TYPE_UNSIGNED32, type_info[i].rangeBegin,
        IPFIX_TYPE_UNSIGNED32, type_info[i].rangeEnd,
        IPFIX_TYPE_STRING, type_info[i].name,
        IPFIX_TYPE_STRING, type_info[i].description,
        IPFIX_TYPE_INVALID
    );
    if (new_ptr == NULL)
      break;
    ptr = new_ptr;
  }
  if (i == sizeof(type_info) / sizeof(type_info[0]))
    *ptype_info_offset = -1;
  else
    *ptype_info_offset = i;

  ptr = ipfix_finalize_set(set_ptr, ptr);

  return ptr;
}

static inline u8 *ipfix_add_flow_key_data_set(u8 *ptr, u8 *end, int *pflow_id_offset)
{
  u8 *set_ptr = ptr;

  ptr = ipfix_prepare_set(set_ptr, end, IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_FLOW_KEYS);

  ptr = ipfix_add_record(ptr, end,
      IPFIX_TYPE_UNSIGNED16, IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_BIRD,
      IPFIX_TYPE_UNSIGNED32, 0x3,
      IPFIX_TYPE_INVALID
  );

  ptr = ipfix_finalize_set(set_ptr, ptr);

  *pflow_id_offset = -1;

  return ptr;
}

static inline u8 *ipfix_add_options_data_set(u8 *ptr, u8 *end, int *pflow_id_offset, int *ptype_info_offset)
{
  if (*pflow_id_offset != -1)
    ptr = ipfix_add_flow_key_data_set(ptr, end, pflow_id_offset);

  if (*ptype_info_offset != -1)
    ptr = ipfix_add_type_info_data_set(ptr, end, ptype_info_offset);

  return ptr;
}

int ipfix_fill_template(
    u8 *ptr,
    u8 *end,
    u32 sequence_number,
    int *ptemplate_offset,
    int *poptions_template_offset,
    int *pflow_id_offset,
    int *ptype_info_offset)
{
  u8 *header_ptr;
  
  header_ptr = ptr;
  ptr = ipfix_prepare_header(header_ptr, sequence_number);

  if (*ptemplate_offset != -1)
    ptr = ipfix_add_template_set(ptr, end, ptemplate_offset);

  if (*poptions_template_offset != -1)
    ptr = ipfix_add_options_template_set(ptr, end, poptions_template_offset);

  if (*pflow_id_offset != -1 || *ptype_info_offset != -1)
    ptr = ipfix_add_options_data_set(ptr, end, pflow_id_offset, ptype_info_offset);

  ipfix_finalize_header(header_ptr, ptr);

  return ptr - header_ptr;
}

int ipfix_fill_counters(u8 *ptr, u8 *end, u32 sequence_number, int *pproto_offset)
{
  int pos;
  int proto_offset = *pproto_offset;
  u8 *header_ptr;
  u8 *set_ptr;
  struct proto *proto;
  int incomplete;

  header_ptr = ptr;

  set_ptr = ipfix_prepare_header(header_ptr, sequence_number);
  ptr = ipfix_prepare_set(set_ptr, end, IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_BIRD);

  pos = 0;
  incomplete = 0;
  WALK_LIST(proto, active_proto_list) {
    if (!proto->cf->ipfix)
      continue;

    if (pos >= proto_offset) {
      u8 *new_ptr = ipfix_add_record(ptr, end,
          IPFIX_TYPE_STRING, proto->name,
          IPFIX_TYPE_UNSIGNED8, IPFIX_INGRESS_FLOW,
          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_routes,
          IPFIX_TYPE_UNSIGNED32, proto->stats.filt_routes,
          IPFIX_TYPE_UNSIGNED32, proto->stats.pref_routes,

          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_updates_received,
          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_updates_invalid,
          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_updates_filtered,
          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_updates_ignored,
          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_updates_accepted,

          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_withdraws_received,
          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_withdraws_invalid,
          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_withdraws_ignored,
          IPFIX_TYPE_UNSIGNED32, proto->stats.imp_withdraws_accepted,

          IPFIX_TYPE_INVALID);

      if (new_ptr == NULL) {
        incomplete = 1;
        break;
      }

      ptr = new_ptr;
    }
    
    ++pos;

    if (pos >= proto_offset) {
      u8 *new_ptr = ipfix_add_record(ptr, end,
          IPFIX_TYPE_STRING, proto->name,
          IPFIX_TYPE_UNSIGNED8, IPFIX_EGRESS_FLOW,
          IPFIX_TYPE_UNSIGNED32, proto->stats.exp_routes,
          IPFIX_TYPE_UNSIGNED32, 0,
          IPFIX_TYPE_UNSIGNED32, 0,

          IPFIX_TYPE_UNSIGNED32, proto->stats.exp_updates_received,
          IPFIX_TYPE_UNSIGNED32, proto->stats.exp_updates_rejected,
          IPFIX_TYPE_UNSIGNED32, proto->stats.exp_updates_filtered,
          IPFIX_TYPE_UNSIGNED32, 0,
          IPFIX_TYPE_UNSIGNED32, proto->stats.exp_updates_accepted,

          IPFIX_TYPE_UNSIGNED32, proto->stats.exp_withdraws_received,
          IPFIX_TYPE_UNSIGNED32, 0,
          IPFIX_TYPE_UNSIGNED32, 0,
          IPFIX_TYPE_UNSIGNED32, proto->stats.exp_withdraws_accepted,

          IPFIX_TYPE_INVALID);

      if (new_ptr == NULL) {
        incomplete = 1;
        break;
      }

      ptr = new_ptr;
    }

    ++pos;
  }

  ptr = ipfix_finalize_set(set_ptr, ptr);
  ipfix_finalize_header(header_ptr, ptr);

  if (incomplete)
    *pproto_offset = pos;
  else
    *pproto_offset = -1;

  return ptr - header_ptr;
}
