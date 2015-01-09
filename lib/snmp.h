/*
 *  BIRD Library -- SNMP notifications
 *
 *  (c) 2015 Peter Nørlund <pch@ordbogen.com>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_SNMP_H_
#define _BIRD_SNMP_H_

typedef enum snmp_value_type
{
  SNMP_INTEGER = 0x02, /* INTEGER */
  SNMP_OCTET_STRING = 0x04, /* OCTET STRING */
  SNMP_OBJECT_IDENTIFIER = 0x06, /* OBJECT IDENTIFIER */
  SNMP_IP_ADDRESS = 0x40, /* IpAddress ::= [APPLICATION 0] */
  SNMP_COUNTER32 = 0x41, /* Counter32 ::= [APPLICATION 1] */
  SNMP_UNSIGNED32 = 0x42, /* Unsigned32 ::= [APPLICATION 2] */
  SNMP_TIME_TICKS = 0x43 /* TimeTicks ::= [APPLICATION 3] */
} snmp_value_type;

typedef int snmp_object_identifier;

#define SNMP_OBJECT_IDENTIFIER(args...) {args, -1}

unsigned int snmp_encode_notification(void *buffer, unsigned int buffer_size, const char *community, const snmp_object_identifier *notification, ...);

#endif /* _BIRD_SNMP_H_ */
