/**
  *  SNMP -- Simple Network Management Protocol
  *
  *  Can be freely distributed and used under the terms of the GNU GPL.
  */

#ifndef _BIRD_NSNMP_H_
#define _BIRD_NSMMP_H_

#include "lib/lists.h"

typedef enum _snmp_varbind_type
{
	SNMP_TYPE_INTEGER32,
	SNMP_TYPE_OCTET_STRING,
	SNMP_TYPE_NULL,
	SNMP_TYPE_OBJECT_IDENTIFIER,
	SNMP_TYPE_IP_ADDRESS,
	SNMP_TYPE_COUNTER32,
	SNMP_TYPE_GAUGE32,
	SNMP_TYPE_TIME_TICKS,
	SNMP_TYPE_OPAQUE,
	SNMP_TYPE_COUNTER64,
	SNMP_TYPE_NO_SUCH_OBJECT,
	SNMP_TYPE_NO_SUCH_INSTANCE,
	SNMP_TYPE_END_OF_MIB_VIEW
} snmp_varbind_type;

typedef struct _snmp_varbind
{
	node n; /* necessary for varbind lists */
	const u32 *oid;
	u8 oid_size;
	u8 type; /* see snmp_varbind_type */
	u8 _oid_is_allocated; /* used internally */
	union
	{
		int integer32;
		struct
		{
			const u8 *str;
			u16 size;
			u8 _is_allocated; /* used internally */
		} string;
		struct
		{
			const u32 *oid;
			u8 size;
			u8 _is_allocated; /* used internally */
		} oid;
		u32 ip_address;
		u32 counter32;
		u32 gauge32;
		u32 time_ticks;
		u64 counter64;
	} value;
} snmp_varbind;

snmp_varbind *snmp_varbind_new_integer32(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, int value);
snmp_varbind *snmp_varbind_new_string(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, const u8 *value, unsigned int length);
snmp_varbind *snmp_varbind_new_string_copy(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, const u8 *value, unsigned int length);
snmp_varbind *snmp_varbind_new_null(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid);
snmp_varbind *snmp_varbind_new_object_id(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, const u32 *value, unsigned int size);
snmp_varbind *snmp_varbind_new_object_id_copy(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, const u32 *value, unsigned int size);
snmp_varbind *snmp_varbind_new_counter32(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, u32 value);
snmp_varbind *snmp_varbind_new_gauge32(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, u32 value);
snmp_varbind *snmp_varbind_new_time_ticks(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, u32 value);
snmp_varbind *snmp_varbind_new_counter64(pool *p, const u32 *oid, unsigned int oid_size, int copy_oid, u64 value);
snmp_varbind *snmp_varbind_copy(pool *p, const snmp_varbind *varbind); 
void snmp_varbind_free(snmp_varbind *varbind);

typedef struct _snmp_registration
{
	node n; /* necessary for registration lists */
	const u32 *oid;
	unsigned int oid_size;
	snmp_varbind *(*get_hook)(const u32 *oid, unsigned int oid_size, void *user_data);
	unsigned int (*get_next_hook)(u32 *oid, unsigned int oid_size, void *user_data); /* oid will contain the current object-id. The hook should replace the oid with the next oid (oid is guaranteed to have room for 128 sub ids) and then return the size. If the end is reached, 0 is returned */
	void *user_data;
} snmp_registration;

void snmp_register(snmp_registration *registration);
void snmp_unregister(snmp_registration *registration);
void snmp_notify(const u32 *oid, unsigned int oid_size, const list *varbinds);

typedef struct _snmp_protocol snmp_protocol;

struct _snmp_protocol
{
	node n; /* For the snmp_protocols list */
	void (*register_hook)(snmp_protocol *p, const snmp_registration *registration, void *user_data);
	void (*unregister_hook)(snmp_protocol *p, const snmp_registration *registration, void *user_data);
	void (*notify_hook)(snmp_protocol *p, const u32 *oid, unsigned int oid_size, const list *varbinds, void *user_data);
	void *user_data;
};

void snmp_init(void);

void snmp_add_protocol(snmp_protocol *protocol);
void snmp_remove_protocol(snmp_protocol *protocol);

struct snmp_global
{
	list protocols;
	list registrations;
};

extern struct snmp_global snmp_global;

#endif /* _BIRD_NSNMP_H_ */
