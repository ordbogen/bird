#include "nest/snmp.h"

#include "nest/bird.h"

#ifdef CONFIG_SNMP

#include "proto/snmp/snmp.h"

#include <stdarg.h>

void snmp_send_notification(const snmp_object_identifier *notification, ...)
{
  if (snmp_instance == NULL)
    return;

  va_list args;
  va_start(args, notification);
  snmp_enqueue_notificationv(snmp_instance, notification, args);
  va_end(args);
}

#endif /* CONFIG_SNMP */
