/*
 *  BIRD -- Simple Network Management Protocol (SNMP)
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#include "nest/bird.h"
#include "snmp.h"
#include "lib/hmac.h"

#include <assert.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>

typedef enum snmp_sequence_type
{
  SNMP_SEQUENCE = 0x30, /* SEQUENCE */
  SNMP_SNMPV2_TRAP_PDU = 0xA7 /* SNMPv2-Trap-PDU ::= [7] IMPLICIT PDU */
} snmp_sequence_type;

enum snmp_security_model
{
  SNMP_USM_SECURITY_MODEL = 0x03,
  SNMP_TSM_SECURITY_MODEL = 0x04
};

#define SNMP_AUTH_FLAG  0x01
#define SNMP_PRIV_FLAG  0x02
#define SNMP_REPORTABLE_FLAG 0x04

/* Encode a signed integer as per ASN.1 BER */
static u8 *snmp_encode_int(u8 *ptr, u8 *end, int value)
{
  /* ASN.1 BER mandates that integers must be encoded with the least number of
     octets possible. The basic rule is that the first octet and bit 8 of the
     second octet must not be all 1s and not be all 0s.

     We figure it out, simple by checking the range of the value. */

  if (ptr == NULL || ptr + 3 >= end)
    return NULL;

  *ptr++ = SNMP_INTEGER;

  if (value >= -128 && value <= 127) {
    *ptr++ = 1;
    *ptr++ = value;
    return ptr;
  }
  else if (value >= -32768 && value <= 32767) {
    if (ptr + 3 >= end)
      return NULL;

    *ptr++ = 2;
    *ptr++ = value >> 8;
    *ptr++ = value;
  }
  else if (value >= -8388608 && value <= 8388607) {
    if (ptr + 4 >= end)
      return NULL;

    *ptr++ = 3;
    *ptr++ = value >> 16;
    *ptr++ = value >> 8;
    *ptr++ = value;
  }
  else {
    if (ptr + 5 >= end)
      return NULL;

    *ptr++ = 4;
    *ptr++ = value >> 24;
    *ptr++ = value >> 16;
    *ptr++ = value >> 8;
    *ptr++ = value;
  }

  return ptr;
}

/* Encode an unsigned integer as per ASN.1 BER */
static u8 *snmp_encode_uint(u8 *ptr, u8 *end, snmp_value_type type, unsigned int value)
{
  /* ASN.1 BER mandates that integers must be encoded with the least number of
     octets possible. The basic rule is that the first octet and bit 8 of the
     second octet must not be all 1s and not be all 0s. With an unsinged integer,
     integers between 2^31 and 2^32-1 will require five octets, with the first
     octet being 0

     We figure it out, simple by checking the range of the value. */

  if (ptr == NULL || ptr + 3 >= end)
    return NULL;

  *ptr++ = type;
  if (value < 128U) {
    *ptr++ = 1;
    *ptr++ = value;
  }
  else if (value < 32768U) {
    if (ptr + 3 >= end)
      return NULL;

    *ptr++ = 2;
    *(u16 *)ptr = htons(value);
  }
  else if (value < 8388607U) {
    if (ptr + 4 >= end)
      return NULL;

    *ptr++ = 3;
    *ptr++ = value >> 16;
    *ptr++ = value >> 8;
    *ptr++ = value;
  }
  else if (value < 2147483648U) {
    if (ptr + 5 >= end)
      return NULL;

    *ptr++ = 4;
    *(u32 *)ptr = htonl(value);
    ptr += 4;
  }
  else {
    if (ptr + 6 >= end)
      return NULL;

    *ptr++ = 5;
    *ptr++ = 0;
    *(u32 *)ptr = htonl(value);
    *ptr++ = 4;
  }

  return ptr;
}

/* Encode an octet string as per ASN.1 BER */
static u8 *snmp_encode_octet_string(u8 *ptr, u8 *end, const void *value, int length)
{
  if (ptr == NULL || ptr + 2 >= end)
    return NULL;

  if (length == -1)
    length = (value == NULL ? 0 : strlen((const char *)value));

  *ptr++ = SNMP_OCTET_STRING;
  if (length < 128)
  {
    /* The length can fit into a single octet */
    if (ptr + 1 + length >= end)
      return NULL;

    *ptr++ = length;
    memcpy(ptr, value, length);
    ptr += length;
  }
  else
  {
    /* The length exceeds that which we can store in a single octet */
    if (ptr + 3 + length >= end)
      return NULL;

    *ptr++ = 0x82;
    *ptr++ = length >> 8;
    *ptr++ = length;

    memcpy(ptr, value, length);
    ptr += length;
  }

  return ptr;
}

/* Encode an object identifier as per ASN.1 BER */
static u8 *snmp_encode_object_identifier(u8 *ptr, u8 *end, const snmp_object_identifier *value)
{
  /*
     BER encoding of object identifiers are rather special. Each subidentifier is encoded in one
     or more octets, each storing 7 bits of the final value. All but the final octet will have
     the 8th bit set to 1.

     Sequences are the only data elements in SNMP where we are allowed to store the length in
     more octets than needed, so knowing beforehand whether we can use a single octet for the
     length, would require us to iterate the entire object identifier. An object identifier
     is however USUALLY not longer than 127 octets, so we optimistically assume than a single
     octet is sufficient for the length. If it isn't, we move the data to make room for a 
     2-octet length */

  u8 *length_ptr;
  int i;
  int length;

  /* An object identifier must have at least two sub identifiers */
  assert(value[0] != -1 && value[1] != -1);

  /* The smallest possible object identifier would require three octets */
  if (ptr == NULL || ptr + 3 >= end)
    return NULL;

  *ptr++ = SNMP_OBJECT_IDENTIFIER;
  length_ptr = ptr++;

  /* The first two sub identifiers are encoded into one octet */
  if (ptr + 1 == end)
    return NULL;
  *ptr++ = value[0] * 40 + value[1];

  /* Encode the rest of the sub identifiers */
  for (i = 2; value[i] != -1; ++i) {
    int subid = value[i];
    if (subid < (1 << 7)) {
      if (ptr + 1 == end)
        return NULL;
      *ptr++ = subid;
    }
    else if (subid < (1 << 14)) {
      if (ptr + 2 >= end)
        return NULL;
      *ptr++ = (subid >> 7) | 0x80;
      *ptr++ = (subid & 0x7F);
    }
    else if (subid < (1 << 21)) {
      if (ptr + 3 >= end)
        return NULL;
      *ptr++ = (subid >> 14) | 0x80;
      *ptr++ = (subid >> 7) | 0x80;
      *ptr++ = (subid & 0x7F);
    }
    else if (subid < (1 << 28)) {
      if (ptr + 4 >= end)
        return NULL;
      *ptr++ = (subid >> 21) | 0x80;
      *ptr++ = (subid >> 14) | 0x80;
      *ptr++ = (subid >> 7) | 0x80;
      *ptr++ = (subid & 0x7F);
    }
    else {
      if (ptr + 5 >= end)
        return NULL;
      *ptr++ = (subid >> 28) | 0x80;
      *ptr++ = (subid >> 21) | 0x80;
      *ptr++ = (subid >> 14) | 0x80;
      *ptr++ = (subid >> 7) | 0x80;
      *ptr++ = (subid & 0x7F);
    }
  }

  /* Update length */

  length = ptr - length_ptr - 1;

  if (length < 128) {
    /* We can store the length into a single octet */
    *length_ptr = length;
  }
  else {
    /* The length exceeded that which we could store in a single octet,
       so we move the data and store the length in 2 octets */

    if (ptr + 2 >= end)
      return NULL;

    memmove(length_ptr + 3, length_ptr + 1, length);

    *length_ptr++ = 0x82;
    *(u16 *)length_ptr = htons(length);

    ptr += 2;
  }

  return ptr;
}

/* Encode an IP address as per SNMPv2-SMI

   SNMP really only supports IPv4 addresses. */
static u8 *snmp_encode_ip_address(u8 *ptr, u8 *end, const ip_addr *ip)
{
  if (ptr + 6 >= end)
    return NULL;

  *ptr++ = SNMP_IP_ADDRESS;
  *ptr++ = 4;

#ifdef IPV6
  *(u32 *)ptr = 0;
#else /* IPV6 */
  *(u32 *)ptr = htonl(ipa_to_u32(*ip));
#endif /* IPV6 */

  ptr += 4;

  return ptr;
}

/* Encode a sequence as per ASN.1 BER

   The sequence is allocated created with an unitialized 2-octet length. */
static u8 *snmp_encode_sequence(u8 *ptr, u8 *end, snmp_sequence_type type, u16 **ppsize)
{
  /* We are allowed to use more octets for sequence length than strictly necessary,
     so we make room for a 16-bit size, so that we can easily update the size later
     regardless of the final size of the message */

  if (ptr == NULL || ptr + 4 >= end)
    return NULL;

  *ptr++ = type;
  *ptr++ = 0x82; /* 2-octet length */

  *ppsize = (u16 *)ptr;
  ptr += 2;

  return ptr;
}

/* Encode a variable binding pair */
static u8 *snmp_encode_varbind(u8 *ptr, u8 *end, const snmp_object_identifier *name, snmp_value_type type, ...)
{
  u8 *varbind_begin;
  u16 *varbind_size;
  va_list args;

  varbind_begin = ptr = snmp_encode_sequence(ptr, end, SNMP_SEQUENCE, &varbind_size);
  if (ptr == NULL)
      return NULL;

  ptr = snmp_encode_object_identifier(ptr, end, name);

  va_start(args, type);

  switch (type) {
    case SNMP_INTEGER:
      ptr = snmp_encode_int(ptr, end, va_arg(args, int));
      break;

    case SNMP_OCTET_STRING:
      {
        const void *data = va_arg(args, const void *);
        int length = va_arg(args, int);
        ptr = snmp_encode_octet_string(ptr, end, data, length);
      }
      break;

    case SNMP_OBJECT_IDENTIFIER:
      ptr = snmp_encode_object_identifier(ptr, end, va_arg(args, const snmp_object_identifier *));
      break;

    case SNMP_IP_ADDRESS:
      ptr = snmp_encode_ip_address(ptr, end, va_arg(args, const ip_addr *));
      break;

    case SNMP_COUNTER32:
    case SNMP_UNSIGNED32:
    case SNMP_TIME_TICKS:
      ptr = snmp_encode_uint(ptr, end, type, va_arg(args, u32));
      break;

    default:
      ptr = NULL;
  }

  va_end(args);

  if (ptr == NULL)
    return NULL;

  *varbind_size = htons(ptr - varbind_begin);

  return ptr;
}

/* Encode a SNMPv2-Trap PDU */
static u8 *snmp_encode_trap_pdu(u8 *ptr, u8 *end, const snmp_object_identifier *notification, va_list args)
{
  /*
     An SNMPv2-Trap PDU is encoded as follows

     snmpV2-trap ::= [7] IMPLICIT SEQUENCE {
       request-id INTEGER,
       error-status INTEGER,
       error-index INTEGER,
       variable-bindings SEQUENCE OF VarBind
     }

     VarBind ::= SEQUENCE {
       name OBJECT IDENTIFIER,
       value ObjectSyntax
     }

     ObjectSyntax ::= CHOICE {
       integer-value          INTEGER (-2147483648..2147483647),
       string-value           OCTET STRING (SIZE (0..65535)),
       objectID-value         OBJECT IDENTIFIER,
       ipAddress-value        [APPLICATION 0] IMPLICIT OCTET STRING (SIZE(4)),
       counter-value          [APPLICATION 1] IMPLICIT INTEGER (0..4294967295),
       unsigned-integer-value [APPLICATION 2] IMPLICIT INTEGER (0..4294967295),
       timeticks-value        [APPLICATION 3] IMPLICIT INTEGER (0..4294967295),
       arbitrary-value        [APPLICATION 4] IMPLICIT OCTET STRING,
       big-counter-value      [APPLICATION 6] IMPLICIT INTEGER (0..18446744073709551615)
     }

     The first two VarBinds MUST be SNMPv2-MIB::sysUpTime.0 and SNMPv2-MIB::snmpTrapOID.0
  */
  static int sequence_id = 0;
  static const snmp_object_identifier sys_up_time[] = SNMP_OBJECT_IDENTIFIER(1, 3, 6, 1, 2, 1, 1, 3, 0);
  static const snmp_object_identifier snmp_trap_oid[] = SNMP_OBJECT_IDENTIFIER(1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0);

  u8 *pdu_begin;
  u16 *pdu_size;
  u8 *varbinds_begin;
  u16 *varbinds_size;

  /* Encode SNMPv2-Trap-PDU sequence */

  pdu_begin = ptr = snmp_encode_sequence(ptr, end, SNMP_SNMPV2_TRAP_PDU, &pdu_size);
  if (ptr == NULL)
    return NULL;

  ptr = snmp_encode_int(ptr, end, sequence_id++); /* sequence-id */
  ptr = snmp_encode_int(ptr, end, 0); /* error-status */
  ptr = snmp_encode_int(ptr, end, 0); /* error-index */

  /* Encode variable-bindings sequence */
  varbinds_begin = ptr = snmp_encode_sequence(ptr, end, SNMP_SEQUENCE, &varbinds_size);
  if (ptr == NULL)
    return NULL;

  /* sysUptime.0 */
  ptr = snmp_encode_varbind(ptr, end, sys_up_time, SNMP_TIME_TICKS, (u32)now);

  /* snmpTrapOID.0 */
  ptr = snmp_encode_varbind(ptr, end, snmp_trap_oid, SNMP_OBJECT_IDENTIFIER, notification);

  for (;;) {
    const snmp_object_identifier *name;
    snmp_value_type type;

    name = va_arg(args, const snmp_object_identifier *);
    if (name == NULL)
      break;

    type = va_arg(args, snmp_value_type);

    switch (type) {
      case SNMP_INTEGER:
        ptr = snmp_encode_varbind(ptr, end, name, SNMP_INTEGER, va_arg(args, int));
        break;

      case SNMP_OCTET_STRING:
        {
          const void *data = va_arg(args, const void *);
          int length = va_arg(args, int);
          ptr = snmp_encode_varbind(ptr, end, name, SNMP_OCTET_STRING, data, length);
        }
        break;

      case SNMP_OBJECT_IDENTIFIER:
        ptr = snmp_encode_varbind(ptr, end, name, SNMP_OBJECT_IDENTIFIER, va_arg(args, const snmp_object_identifier *));
        break;

      case SNMP_IP_ADDRESS:
        ptr = snmp_encode_varbind(ptr, end, name, SNMP_IP_ADDRESS, va_arg(args, const ip_addr *));
        break;

      case SNMP_COUNTER32:
      case SNMP_UNSIGNED32:
      case SNMP_TIME_TICKS:
        ptr = snmp_encode_varbind(ptr, end, name, type, va_arg(args, u32));
        break;

      default:
        ptr = NULL;
    }

    if (ptr == NULL)
      break;
  }

  /* Update sizes */
  *pdu_size = htons(ptr - pdu_begin);
  *varbinds_size = htons(ptr - varbinds_begin);

  return ptr;
}

/* Encode SNMPv2c notification */
static u8 *snmp_encode_snmpv2c_trap(u8 *ptr, u8 *end, const struct snmp_params *params, const snmp_object_identifier *notification, va_list args)
{
  /*
     The SNMPv2c message follows the following syntax:

     Message ::= SEQUENCE {
       version INTEGER { version(1) },
       community OCTET STRING,
       data ANY
     }

     See RFC 1901 for more details
  */
  u8 *message_begin;
  u16 *message_size;

  /* Encode message sequence */
  message_begin = ptr = snmp_encode_sequence(ptr, end, SNMP_SEQUENCE, &message_size);
  if (ptr == NULL)
    return NULL;

  ptr = snmp_encode_int(ptr, end, 1); /* version */
  ptr = snmp_encode_octet_string(ptr, end, params->community, -1); /* community */

  ptr = snmp_encode_trap_pdu(ptr, end, notification, args);

  /* Update sizes */
  *message_size = htons(ptr - message_begin);

  return ptr;
}

static u8 *snmp_encode_security_params_init(u8 *ptr, u8 *end, const struct snmp_params *params, u8 **pmsg_auth_params)
{
  if (ptr == NULL) {
    return NULL;
  }
  else if (params->version == SNMP_VERSION_2C) {
    return ptr;
  }
  else /*if (params->version == SNMP_VERSION_3)*/ {
    /*
      The security parameters of SNMPv3 USM follows the following syntax:

      UsmSecurityParameters ::= SEQUENCE {
        msgAuthoritativeEngineID OCTET STRING,
        msgAuthoritativeEngineBoots INTEGER (0..2147483647),
        msgAuthoritativeEngineTime INTEGER (0..2147483647),
        msgUserName OCTET STRING (SIZE(0..32))
        msgAuthenticationParameters OCTET STRING
        msgPrivacyParameters OCTET STRING
      }

      The security parameters are serialize and stored within an OCTET STRING

      With the usmHMACMD5AuthProtocol and usnNoPrivProtocol, the maximum size of the UsmSecurityParameters is:

      SEQUENCE:                     4 octets (snmp_encode_sequence always allocate 16-bit size)
      msgAuthoritativeEngineID:    34 octets (EngineID cannot exceed 32 octets)
      msgAuthoritativeEngineBoots:  6 octets
      msgAuthoritativeEngineTime:   6 octets
      msgUserName:                 34 octets
      msgAuthenticationParameters: 14 octets (msgAuthenticationParameters is either 0 or 12 octets)
      msgPrivacyParameters:         2 octets (in this case, it is always empty)
      --------------------------------------
      Total:                      100 octets

      This means that we can guaranetee that the size of msgSecurityParameters will not exceed 2 octets
    */

    u8 *security_params_begin;
    u16 *security_params_size;
    u8 *octet_string_size;
    u8 *octet_string_begin;
    static const u8 placeholder[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /* Create OCTET STRING header */
    if (ptr + 2 >= end)
      return NULL;

    *ptr++ = SNMP_OCTET_STRING;
    octet_string_size = ptr;
    octet_string_begin = ++ptr;

    /* Encode UsmSecurityParameters sequence */

    security_params_begin = ptr = snmp_encode_sequence(ptr, end, SNMP_SEQUENCE, &security_params_size);
    if (ptr == NULL)
      return NULL;

    ptr = snmp_encode_octet_string(ptr, end, params->auth_engine_id, params->auth_engine_id_length); /* msgAuthoritativeEngineID */
    ptr = snmp_encode_int(ptr, end, 0); /* msgAuthoritativeEngineBoots */
    ptr = snmp_encode_int(ptr, end, 0); /* msgAuthoritativeEngineTime */
    ptr = snmp_encode_octet_string(ptr, end, params->username, -1); /* msgUserName */

    if (params->key_length != 0) {
      *pmsg_auth_params = ptr + 2;
      ptr = snmp_encode_octet_string(ptr, end, placeholder, 12); /* msgAuthenticationParameters */
    }
    else {
      *pmsg_auth_params = NULL;
      ptr = snmp_encode_octet_string(ptr, end, NULL, 0); /* msgAuthenticationParameters */
    }
    ptr = snmp_encode_octet_string(ptr, end, NULL, 0); /* msgPrivacyParameters */

    *security_params_size = htons(ptr - security_params_begin);

    /* End of UsmSecurityParameters sequence */

    *octet_string_size = ptr - octet_string_begin;
  }

  return ptr;
}

static void snmp_encode_security_params_final(const u8 *ptr, const u8 *end, const struct snmp_params *params, u8 *msg_auth_params)
{
  unsigned char digest[16];

  if (params->version != SNMP_VERSION_3 || params->username == NULL || params->key_length == 0)
    return;

  // HMAC-MD5-96
  hmac_md5(ptr, end - ptr, params->key, sizeof(params->key), digest);
  memcpy(msg_auth_params, digest, 12);
}

/* Encode SNMPv3 notification */
static u8 *snmp_encode_snmpv3_trap(u8 *ptr, u8 *end, const struct snmp_params *params, const snmp_object_identifier *notification, va_list args)
{
  /*
     The SNMPv3 message follows the following syntax:

     SNMPv3Message ::= SEQUENCE {
       msgVersion INTEGER (0..2147483647),
       msgGlobalData HeaderData,
       msgSecurityParameters OCTET STRING,
       msgData ScopedPduData
     }

     HeaderData ::= SEQUENCE {
       msgID INTEGER (0..2147483647),
       msgMaxSize INTEGER (484..2147483647),
       msgFlags OCTET STRING (SIZE(1)),
       msgSecurityModel INTEGER(1..2147483647)
     }

     ScopedPduData ::= CHOICE {
       plaintext ScopedPDU,
       encryptedPDU OCTET STRING
     }

     ScopedPdu ::= SEQUENCE {
       contextEngineID OCTET STRING,
       contextName OCTET STRING,
       data ANY
     }

     See RFC 3412 for more details
  */
  u8 *trap_start = ptr;

  u8 *message_begin;
  u16 *message_size;

  u8 *global_data_begin;
  u16 *global_data_size;

  u8 *scoped_pdu_begin;
  u16 *scoped_pdu_size;

  u8 *msg_auth_params;

  u8 msg_flags;

  /* Encode SNMPv3Message sequence */
  message_begin = ptr = snmp_encode_sequence(ptr, end, SNMP_SEQUENCE, &message_size);
  if (ptr == NULL)
    return NULL;

  ptr = snmp_encode_int(ptr, end, 3); /* msgVersion */

  /* Encode msgGlobalData sequence */

  global_data_begin = ptr = snmp_encode_sequence(ptr, end, SNMP_SEQUENCE, &global_data_size);
  if (ptr == NULL)
    return NULL;

  ptr = snmp_encode_int(ptr, end, 0); /* msgID */
  ptr = snmp_encode_int(ptr, end, SNMP_MAX_PAYLOAD); /* msgMaxSize */

  if (params->key_length != 0)
    msg_flags = 0x01; // authNoPriv
  else
    msg_flags = 0x00; // noAuthNoPriv
  ptr = snmp_encode_octet_string(ptr, end, &msg_flags, 1); /* msgFlags */

  ptr = snmp_encode_int(ptr, end, SNMP_USM_SECURITY_MODEL); /* msgSecurityModel */

  *global_data_size = htons(ptr - global_data_begin);

  /* End of msgGlobalData sequence */

  ptr = snmp_encode_security_params_init(ptr, end, params, &msg_auth_params); /* msgSecurityParameters */
  if (ptr == NULL)
    return NULL;

  /* Encode msgData sequence */

  scoped_pdu_begin = ptr = snmp_encode_sequence(ptr, end, SNMP_SEQUENCE, &scoped_pdu_size);
  if (ptr == NULL)
    return NULL;

  ptr = snmp_encode_octet_string(ptr, end, params->context_engine_id, params->context_engine_id_length); /* contextEngineID */
  ptr = snmp_encode_octet_string(ptr, end, params->context_name, -1); /* contextName */
  ptr = snmp_encode_trap_pdu(ptr, end, notification, args); /* data */
  *scoped_pdu_size = htons(ptr - scoped_pdu_begin);

  /* End of msgData sequence */

  *message_size = htons(ptr - message_begin);

  /* End of SNMPv3Message sequence */

  if (ptr != NULL && msg_auth_params != NULL)
    snmp_encode_security_params_final(trap_start, ptr, params, msg_auth_params); /* Update password if any */

  return ptr;
}

/* Encode a SNMP notification

   Returns the size of the notification in octets or 0 if buffer is too small. */
unsigned int snmp_encode_notificationv(void *buffer, unsigned int buffer_size, const struct snmp_params *params, const snmp_object_identifier *notification, va_list args)
{
  u8 *begin = (u8 *)buffer;
  u8 *end = begin + buffer_size;
  u8 *ptr = begin;

  if (params->version == SNMP_VERSION_2C)
    ptr = snmp_encode_snmpv2c_trap(ptr, end, params, notification, args);
  else /* if (params->version == SNMP_VERSION_3) */
    ptr = snmp_encode_snmpv3_trap(ptr, end, params, notification, args);

  if (ptr == NULL)
    return 0;

  return ptr - begin;
}
