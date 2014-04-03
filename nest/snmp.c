#include "nest/bird.h"
#include "nest/snmp.h"

#include <string.h>

struct snmp_global snmp_global;

void snmp_init(void)
{
  init_list(&snmp_global.protocols);
  snmp_global.registrations = oidlist_new(&root_pool);
}

void snmp_add_protocol(snmp_protocol *protocol)
{
  add_tail(&snmp_global.protocols, &protocol->n);
}

void snmp_remove_protocol(snmp_protocol *protocol)
{
  rem_node(&protocol->n);
}

void snmp_register(const u32 *oid, unsigned int oidlen, snmp_registration *registration)
{
  snmp_protocol *protocol;

  oidlist_set(snmp_global.registrations, oid, oidlen, registration);

  WALK_LIST(protocol, snmp_global.protocols)
  {
    protocol->register_hook(protocol, registration);
  }
}

void snmp_unregister(const u32 *oid, unsigned int oidlen)
{
  snmp_protocol *protocol;
  snmp_registration *registration;
  oiditer *iter;

  iter = oidlist_find(snmp_global.registrations, oid, oidlen);
  if (iter == NULL)
    return;

  registration = (snmp_registration *)oiditer_value(iter);

  oiditer_unset(iter);
  oiditer_free(iter);
  
  WALK_LIST(protocol, snmp_global.protocols)
  {
    protocol->unregister_hook(protocol, registration);
  }
}

void snmp_notify(const u32 *oid, unsigned int oidlen, const list *varbinds)
{
  snmp_protocol *protocol;
  WALK_LIST(protocol, snmp_global.protocols)
  {
    protocol->notify_hook(protocol, oid, oidlen, varbinds);
  }
}

static snmp_varbind *snmp_varbind_allocate(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, snmp_varbind_type type, unsigned int data_size, void **data_ptr)
{
  snmp_varbind *varbind;
  if (copy_oid)
  {
    u32 *buffer;
    varbind = (snmp_varbind *)mb_alloc(p, sizeof(*varbind) + oidlen * sizeof(oid[0]) + data_size);
    buffer = (u32 *)&varbind[1];
    memcpy(buffer, oid, oidlen * sizeof(oid[0]));
    varbind->oid = buffer;
    varbind->_oid_is_allocated = 1;

    if (data_ptr)
      *data_ptr = &buffer[oidlen];
  }
  else
  {
    varbind = (snmp_varbind *)mb_alloc(p, sizeof(*varbind) + data_size);
    varbind->oid = oid;
    varbind->_oid_is_allocated = 0;

    if (data_ptr)
      *data_ptr = &varbind[1];
  }
  varbind->n.next = NULL;
  varbind->n.prev = NULL;
  varbind->oidlen = oidlen;
  varbind->type = type;
  return varbind;
}

snmp_varbind *snmp_varbind_new_integer32(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, int value)
{
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_INTEGER32, 0, NULL);
  varbind->value.integer32 = value;
  return varbind;
}

snmp_varbind *snmp_varbind_new_string(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, const u8 *value, unsigned int size)
{
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_OCTET_STRING, 0, NULL);
  varbind->value.string.str = value;
  varbind->value.string.size = size;
  varbind->value.string._is_allocated = 0;
  return varbind;
}

snmp_varbind *snmp_varbind_new_string_copy(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, const u8 *value, unsigned int size)
{
  u8 *buffer;
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_OCTET_STRING, size, (void **)&buffer);
  memcpy(buffer, value, size);
  varbind->value.string.str = buffer;
  varbind->value.string.size = size;
  varbind->value.string._is_allocated = 1;
  return varbind;
}

snmp_varbind *snmp_varbind_new_null(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid)
{
  return snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_NULL, 0, NULL);
}

snmp_varbind *snmp_varbind_new_object_id(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, const u32 *value, unsigned int size)
{
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_OCTET_STRING, 0, NULL);
  varbind->value.oid.oid = value;
  varbind->value.oid.size = size;
  varbind->value.oid._is_allocated = 0;
  return varbind;
}

snmp_varbind *snmp_varbind_new_object_id_copy(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, const u32 *value, unsigned int size)
{
  u32 *buffer;
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_OCTET_STRING, size * sizeof(value[0]), (void **)&buffer);
  memcpy(buffer, value, size * sizeof(value[0]));
  varbind->value.oid.oid = buffer;
  varbind->value.oid.size = size;
  varbind->value.oid._is_allocated = 1;
  return varbind;
}

snmp_varbind *snmp_varbind_new_counter32(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, u32 value)
{
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_COUNTER32, 0, NULL);
  varbind->value.counter32 = value;
  return varbind;
}

snmp_varbind *snmp_varbind_new_gauge32(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, u32 value)
{
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_GAUGE32, 0, NULL);
  varbind->value.gauge32 = value;
  return varbind;
}

snmp_varbind *snmp_varbind_new_time_ticks(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, u32 value)
{
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_TIME_TICKS, 0, NULL);
  varbind->value.time_ticks = value;
  return varbind;
}

snmp_varbind *snmp_varbind_new_counter64(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid, u64 value)
{
  snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_COUNTER64, 0, NULL);
  varbind->value.counter64 = value;
  return varbind;
}

snmp_varbind *snmp_varbind_new_no_such_object(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid)
{
  return snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_NO_SUCH_OBJECT, 0, NULL);
}

snmp_varbind *snmp_varbind_new_no_such_instance(pool *p, const u32 *oid, unsigned int oidlen, int copy_oid)
{
  return snmp_varbind_allocate(p, oid, oidlen, copy_oid, SNMP_TYPE_NO_SUCH_INSTANCE, 0, NULL);
}

snmp_varbind *snmp_varbind_copy(pool *p, const snmp_varbind *varbind)
{
  switch ((snmp_varbind_type)varbind->type)
  {
    case SNMP_TYPE_INTEGER32:
      return snmp_varbind_new_integer32(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.integer32);

    case SNMP_TYPE_OCTET_STRING:
      if (varbind->value.string._is_allocated)
	return snmp_varbind_new_string_copy(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.string.str, varbind->value.string.size);
      else
	return snmp_varbind_new_string(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.string.str, varbind->value.string.size);

    case SNMP_TYPE_OBJECT_IDENTIFIER:
      if (varbind->value.oid._is_allocated)
	return snmp_varbind_new_object_id_copy(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.oid.oid, varbind->value.oid.size);
      else
	return snmp_varbind_new_object_id(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.oid.oid, varbind->value.oid.size);

    case SNMP_TYPE_COUNTER32:
      return snmp_varbind_new_counter32(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.counter32);

    case SNMP_TYPE_GAUGE32:
      return snmp_varbind_new_gauge32(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.gauge32);

    case SNMP_TYPE_TIME_TICKS:
      return snmp_varbind_new_time_ticks(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.time_ticks);

    case SNMP_TYPE_COUNTER64:
      return snmp_varbind_new_counter64(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->value.counter64);

    case SNMP_TYPE_OPAQUE:
    case SNMP_TYPE_IP_ADDRESS:
      /* TODO */
      break;

    case SNMP_TYPE_NULL:
    case SNMP_TYPE_NO_SUCH_OBJECT:
    case SNMP_TYPE_NO_SUCH_INSTANCE:
    case SNMP_TYPE_END_OF_MIB_VIEW:
      return snmp_varbind_allocate(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, varbind->type, 0, NULL);
  }

  return snmp_varbind_allocate(p, varbind->oid, varbind->oidlen, varbind->_oid_is_allocated, SNMP_TYPE_NULL, 0, NULL);
}

void snmp_varbind_free(snmp_varbind *varbind)
{
  rem_node(&varbind->n);
  mb_free(varbind);
}
