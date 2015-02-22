#include "snmp.h"

/**
 * snmp_send_notification - Send SNMP notification
 * @notification: Notification identifier
 *
 * Generates an SNMP notification with a series of SNMP values.
 *
 * You specify the values in name-type-value pairs. The first two
 * arguments are const snmp_object_identifier *, and snmp_value_type
 * respectively. The type of the third argument depends on the
 * snmp_value_type.
 *
 * Octet strings has a fouth argument with the size of the string.
 * -1 denotes zero-terminated string.
 *
 * The types (and their respective arguments) are:
 *
 * SNMP_INTEGER (int)
 *
 * SNMP_OCTET_STRING (const void *, int)
 *
 * SNMP_OCTET_IDENTIFIER (const snmp_object_identifier *)
 *
 * SNMP_IP_ADDRESS (const struct ip_addr *)
 *
 * SNMP_COUNTER32 (unsigned int)
 *
 * SNMP_UNSIGNED32 (unsigned int)
 *
 * SNMP_TIME_TICKS (unsigned int)
 */
void snmp_send_notification(const snmp_object_identifier *notification, ...)
{
  va_list args;
  if (snmp_instance == NULL)
    return;

  va_start(args, notification);
  snmp_enqueue_notificationv(snmp_instance, notification, args);
  va_end(args);
}
