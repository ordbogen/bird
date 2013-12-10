#include "nest/snmp.h"

#include <string.h>

list snmp_protocols;

void snmp_init_protocols(void)
{
	init_list(&snmp_protocols);
}

void snmp_add_protocol(snmp_protocol *protocol)
{
	add_tail(&snmp_protocols, &protocol->n);
}

void snmp_remove_protocol(snmp_protocol *protocol)
{
	rem_node(&protocol->n);
}

void snmp_register(const snmp_registration *registration)
{
	snmp_protocol *protocol;
	WALK_LIST(protocol, snmp_protocols)
	{
		protocol->register_hook(protocol, registration, protocol->user_data);
	}
}

void snmp_unregister(const snmp_registration *registration)
{
	snmp_protocol *protocol;
	WALK_LIST(protocol, snmp_protocols)
	{
		protocol->unregister_hook(protocol, registration, protocol->user_data);
	}
}

void snmp_notify(const u32 *oid, unsigned int oid_size, const list *varbinds)
{
	snmp_protocol *protocol;
	WALK_LIST(protocol, snmp_protocols)
	{
		protocol->notify_hook(protocol, oid, oid_size, varbinds, protocol->user_data);
	}
}

static snmp_varbind *snmp_varbind_allocate(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, snmp_varbind_type type, unsigned int data_size)
{
	snmp_varbind *varbind;
	if (copy_oid)
	{
		u32 *buffer;
		varbind = (snmp_varbind *)mb_alloc(p, sizeof(*varbind) + oid_size * sizeof(oid[0]) + data_size);
		buffer = (u32 *)&varbind[1];
		memcpy(buffer, oid, oid_size * sizeof(oid[0]));
		varbind->oid = buffer;
		varbind->_oid_is_allocated = 1;
	}
	else
	{
		varbind = (snmp_varbind *)mb_alloc(p, sizeof(*varbind) + data_size);
		varbind->oid = oid;
		varbind->_oid_is_allocated = 0;
	}
	varbind->n.next = NULL;
	varbind->n.prev = NULL;
	varbind->oid_size = oid_size;
	varbind->type = type;
	return varbind;
}

snmp_varbind *snmp_varbind_new_integer32(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, int value)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_INTEGER32, 0);
	varbind->value.integer32 = value;
	return varbind;
}

snmp_varbind *snmp_varbind_new_string(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, const u8 *value, unsigned int size)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_OCTET_STRING, 0);
	varbind->value.string.str = value;
	varbind->value.string.size = size;
	varbind->value.string._is_allocated = 0;
	return varbind;
}

snmp_varbind *snmp_varbind_new_string_copy(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, const u8 *value, unsigned int size)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_OCTET_STRING, size);
	u8 *buffer = (u8 *)&varbind[1];
	memcpy(buffer, value, size);
	varbind->value.string.str = buffer;
	varbind->value.string.size = size;
	varbind->value.string._is_allocated = 1;
	return varbind;
}

snmp_varbind *snmp_varbind_new_null(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid)
{
	return snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_NULL, 0);
}

snmp_varbind *snmp_varbind_new_object_id(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, const u32 *value, unsigned int size)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_OCTET_STRING, 0);
	varbind->value.oid.oid = value;
	varbind->value.oid.size = size;
	varbind->value.oid._is_allocated = 0;
	return varbind;
}

snmp_varbind *snmp_varbind_new_object_id_copy(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, const u32 *value, unsigned int size)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_OCTET_STRING, size * sizeof(value[0]));
	u32 *buffer = (u32 *)&varbind[1];
	memcpy(buffer, value, size * sizeof(value[0]));
	varbind->value.oid.oid = buffer;
	varbind->value.oid.size = size;
	varbind->value.oid._is_allocated = 1;
	return varbind;
}

snmp_varbind *snmp_varbind_new_counter32(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, u32 value)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_COUNTER32, 0);
	varbind->value.counter32 = value;
	return varbind;
}

snmp_varbind *snmp_varbind_new_gauge32(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, u32 value)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_GAUGE32, 0);
	varbind->value.gauge32 = value;
	return varbind;
}

snmp_varbind *snmp_varbind_new_time_ticks(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, u32 value)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_TIME_TICKS, 0);
	varbind->value.time_ticks = value;
	return varbind;
}

snmp_varbind *snmp_varbind_new_counter64(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, u64 value)
{
	snmp_varbind *varbind = snmp_varbind_allocate(p, oid, oid_size, copy_oid, SNMP_TYPE_COUNTER64, 0);
	varbind->value.counter64 = value;
	return varbind;
}

snmp_varbind *snmp_varbind_copy(pool *p, const snmp_varbind *varbind)
{
	switch ((snmp_varbind_type)varbind->type)
	{
		case SNMP_TYPE_INTEGER32:
			return snmp_varbind_new_integer32(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.integer32);

		case SNMP_TYPE_OCTET_STRING:
			if (varbind->value.string._is_allocated)
				return snmp_varbind_new_string_copy(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.string.str, varbind->value.string.size);
			else
				return snmp_varbind_new_string(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.string.str, varbind->value.string.size);

		case SNMP_TYPE_OBJECT_IDENTIFIER:
			if (varbind->value.oid._is_allocated)
				return snmp_varbind_new_object_id_copy(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.oid.oid, varbind->value.oid.size);
			else
				return snmp_varbind_new_object_id(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.oid.oid, varbind->value.oid.size);

		case SNMP_TYPE_COUNTER32:
			return snmp_varbind_new_counter32(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.counter32);

		case SNMP_TYPE_GAUGE32:
			return snmp_varbind_new_gauge32(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.gauge32);

		case SNMP_TYPE_TIME_TICKS:
			return snmp_varbind_new_time_ticks(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.time_ticks);
			
		case SNMP_TYPE_COUNTER64:
			return snmp_varbind_new_counter64(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->value.counter64);

		case SNMP_TYPE_OPAQUE:
		case SNMP_TYPE_IP_ADDRESS:
			/* TODO */
			break;

		case SNMP_TYPE_NULL:
		case SNMP_TYPE_NO_SUCH_OBJECT:
		case SNMP_TYPE_NO_SUCH_INSTANCE:
		case SNMP_TYPE_END_OF_MIB_VIEW:
			return snmp_varbind_allocate(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, varbind->type, 0);
	}

	return snmp_varbind_allocate(p, varbind->oid, varbind->oid_size, varbind->_oid_is_allocated, SNMP_TYPE_NULL, 0);
}

void snmp_varbind_free(snmp_varbind *varbind)
{
	rem_node(&varbind->n);
	mb_free(varbind);
}
