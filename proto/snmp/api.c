#include "snmp.h"

void snmp_send_notification(const snmp_object_identifier *notification, ...)
{
  if (snmp_instance == NULL)
    return;

  va_list args;
  va_start(args, notification);
  snmp_enqueue_notificationv(snmp_instance, notification, args);
  va_end(args);
}
