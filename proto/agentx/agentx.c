#include "agentx.h"

static void agentx_register_hook(snmp_protocol *snmp, const snmp_registration *registration)
{
	struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
	if (p->state == AGENTX_STATE_ESTABLISHED)
	{
		/* TODO */
	}
}

static void agentx_unregister_hook(snmp_protocol *snmp, const snmp_registration *registration)
{
	struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
	if (p->state == AGENTX_STATE_ESTABLISHED)
	{
		/* TODO */
	}
}

static void agentx_notify_hook(snmp_protocol *snmp, const u32 *oid, unsigned int oid_size, const list *varbinds)
{
	struct agentx_proto *p = (struct agentx_proto *)snmp->user_data;
	if (p->state == AGENTX_STATE_ESTABLISHED)
	{
		/* TODO */
	}
}

static struct proto *agentx_init(struct proto_config *C)
{
	struct agentx_proto *p = (struct agentx_proto *)proto_new(C, sizeof(*p));

	p->cf = (struct agentx_config *)C;

	p->snmp.register_hook = agentx_register_hook;
	p->snmp.unregister_hook = agentx_unregister_hook;
	p->snmp.notify_hook = agentx_notify_hook;
	p->snmp.user_data = (void *)p;

	p->state = AGENTX_STATE_DISABLED;
	p->sk = NULL;
	p->session_id = 0;

	return &p->p;
}

static int agentx_start(struct proto *P)
{
	struct agentx_proto *p = (struct agentx_proto *)P;

	snmp_add_protocol(&p->snmp);

	return PS_START;
}

static int agentx_shutdown(struct proto *P)
{
	struct agentx_proto *p = (struct agentx_proto *)P;

	snmp_remove_protocol(&p->snmp);

	return PS_DOWN;
}

struct protocol proto_agentx = {
	.name =				"AgentX",
	.template =			"agentx%d",
	.init =				agentx_init,
	.start =			agentx_start,
	.shutdown =			agentx_shutdown,
};
