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

static inline u8* ipfix_prepare_header(u8* ptr, u32 sequence_number)
{
  struct ipfix_message_header *header = (struct ipfix_message_header *)ptr;
  header->version_number = htons(10);
  /* header->length = 0; */
  header->export_time = htonl(now);
  header->sequence_number = htonl(sequence_number);
  header->observation_domain_id = 0;

  return ptr + sizeof(struct ipfix_message_header);
}

static inline void ipfix_finalize_header(u8* ptr, u8* end)
{
  struct ipfix_message_header *header = (struct ipfix_message_header *)ptr;
  header->length = htons(end - ptr);
}

static inline u8 *ipfix_prepare_set(u8 *ptr, u16 set_id)
{
  struct ipfix_set_header *header = (struct ipfix_set_header *)ptr;
  header->set_id = htons(set_id);
  return ptr + sizeof(struct ipfix_set_header);
}

static inline void ipfix_finalize_set(u8 *ptr, u8 *end)
{
  struct ipfix_set_header *header = (struct ipfix_set_header *)ptr;
  header->length = htons(end - ptr);
}

static inline u8 *ipfix_add_template_record(
    u8 *ptr,
    u16 template_id,
    u16 field_count)
{
  struct ipfix_template_record_header *header = (struct ipfix_template_record_header *)ptr;
  header->template_id = htons(template_id);
  header->field_count = htons(field_count);
  return ptr + sizeof(*header);
}

static inline u8 *ipfix_add_options_template_record(
    u8 *ptr,
    u16 template_id,
    u16 field_count,
    u16 scope_field_count)
{
  struct ipfix_option_template_record_header *header = (struct ipfix_option_template_record_header *)ptr;
  header->template_id = htons(template_id);
  header->field_count = htons(field_count);
  header->scope_field_count = htons(scope_field_count);
  return ptr + sizeof(*header);
}

static inline u8 *ipfix_add_field_specifier(
    u8 *ptr,
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

static inline u8 *ipfix_add_string(u8 *ptr, const char *string)
{
  int length = strlen(string);
  if (length < 256)
  {
    *ptr++ = length;
  }
  else
  {
    *ptr++ = 255;
    *(u16 *)ptr = htons(length);
    ptr += 2;
  }

  memcpy(ptr, string, length);
  return ptr + length;
}

static inline u8 *ipfix_add_template_set(u8 *ptr)
{
  u8 *set_ptr = ptr;
  
  ptr = ipfix_prepare_set(set_ptr, IPFIX_TEMPLATE_SET);

  ptr = ipfix_add_template_record(
      ptr,
      IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_BIRD,
      3);

  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_BIRD_NAME, 65535, IPFIX_ENTERPRISE_ORDBOGEN); /* Scope */
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_BIRD_UPDATES, 4, IPFIX_ENTERPRISE_ORDBOGEN);
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_BIRD_WITHDRAWALS, 4, IPFIX_ENTERPRISE_ORDBOGEN);

  ipfix_finalize_set(set_ptr, ptr);

  return ptr;
}

static inline u8 *ipfix_add_flow_keys_template(u8 *ptr)
{
  ptr = ipfix_add_options_template_record(
      ptr,
      IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_FLOW_KEYS,
      2,
      1
  );

  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_TEMPLATE_ID, 2, 0); /* Scope */
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_FLOW_KEY_INDICATOR, 8, 0);

  return ptr;
}

static inline u8 *ipfix_add_type_info_template(u8 *ptr)
{
  ptr = ipfix_add_options_template_record(
      ptr,
      IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_TYPE_INFO,
      9, /* Total number of field identifiers */
      2  /* Number of scope identifiers */
  );

  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_INFORMATION_ELEMENT_ID, 2, 0); /* Scope */
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_PRIVATE_ENTERPRISE_NUMBER, 4, 0); /* Scope */
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_INFORMATION_ELEMENT_DATA_TYPE, 1, 0);
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_INFORMATION_ELEMENT_SEMANTICS, 1, 0);
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_INFORMATION_ELEMENT_UNITS, 1, 0);
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_INFORMATION_ELEMENT_RANGE_BEGIN, 8, 0);
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_INFORMATION_ELEMENT_RANGE_END, 8, 0);
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_INFORMATION_ELEMENT_NAME, 65535, 0);
  ptr = ipfix_add_field_specifier(ptr, IPFIX_IE_INFORMATION_ELEMENT_DESCRIPTION, 65535, 0);

  return ptr;
}

static inline u8 *ipfix_add_options_template_set(u8 *ptr)
{
  u8 *set_ptr = ptr;
  
  ptr = ipfix_prepare_set(set_ptr, IPFIX_OPTIONS_TEMPLATE_SET);

  ptr = ipfix_add_flow_keys_template(ptr);
  ptr = ipfix_add_type_info_template(ptr);

  ipfix_finalize_set(set_ptr, ptr);

  return ptr;
}

static inline u8 *ipfix_add_flow_key(u8 *ptr, u16 template_id, u32 keys)
{
  *(u16 *)ptr = htons(template_id);
  ptr += 2;

  *(u32 *)ptr = 0;
  ptr += 4;

  *(u32 *)ptr = htonl(keys);
  ptr += 4;

  return ptr;
}

static inline u8 *ipfix_add_type_info(u8 *ptr,
    u16 id,
    u32 enterprise_number,
    u8 type,
    u8 semantic,
    u8 unit,
    u32 range_begin,
    u32 range_end,
    const char *name,
    const char *description)
{
  *(u16 *)ptr = htons(id);
  ptr += 2;

  *(u32 *)ptr = htonl(enterprise_number);
  ptr += 4;

  *ptr++ = type;
  *ptr++ = semantic;
  *ptr++ = unit;

  *(u32 *)ptr = 0;
  ptr += 4;
  *(u32 *)ptr = htonl(range_begin);
  ptr += 4;

  *(u32 *)ptr = 0;
  ptr += 4;
  *(u32 *)ptr = htonl(range_end);
  ptr += 4;

  ptr = ipfix_add_string(ptr, name);
  ptr = ipfix_add_string(ptr, description);

  return ptr;
}

static inline u8 *ipfix_add_options_data_set(u8 *ptr)
{
  u8 *set_ptr;
  
  set_ptr = ptr;
  ptr = ipfix_prepare_set(set_ptr, IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_FLOW_KEYS);
  ptr = ipfix_add_flow_key(ptr, IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_BIRD, 1);
  ipfix_finalize_set(set_ptr, ptr);


  set_ptr = ptr;
  ptr = ipfix_prepare_set(set_ptr, IPFIX_DATA_SET_BASE + IPFIX_DATA_SET_INDEX_TYPE_INFO);

  ptr = ipfix_add_type_info(ptr,
      IPFIX_IE_BIRD_NAME,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_STRING,
      IPFIX_SEMANTIC_DEFAULT,
      IPFIX_UNIT_NONE,
      0,
      0,
      "name",
      "Name of BIRD protocol");

  ptr = ipfix_add_type_info(ptr,
      IPFIX_IE_BIRD_UPDATES,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_NONE,
      0,
      0xFFFFFFFF,
      "updates",
      "Total number of route updates");

  ptr = ipfix_add_type_info(ptr,
      IPFIX_IE_BIRD_WITHDRAWALS,
      IPFIX_ENTERPRISE_ORDBOGEN,
      IPFIX_TYPE_UNSIGNED32,
      IPFIX_SEMANTIC_TOTAL_COUNTER,
      IPFIX_UNIT_NONE,
      0,
      0xFFFFFFFF,
      "withdrawals",
      "Total number of route withdrawals");

  ipfix_finalize_set(set_ptr, ptr);

  return ptr;
}


int ipfix_fill_template(sock *sk, u32 sequence_number)
{
  /* UDP packets must not exceed 512 bytes, so neither should the template */
  u8 *header_ptr;
  u8 *ptr;
  
  header_ptr = sk->tbuf;
  ptr = ipfix_prepare_header(header_ptr, sequence_number);

  ptr = ipfix_add_template_set(ptr);
  ptr = ipfix_add_options_template_set(ptr);
  ptr = ipfix_add_options_data_set(ptr);

  ipfix_finalize_header(header_ptr, ptr);

  return ptr - header_ptr;
}
