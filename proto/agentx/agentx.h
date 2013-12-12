/*
 *  BIRD -- Agent Extensibility (AgentX) Protocol
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_AGENTX_H_
#define _BIRD_AGENTX_H_

#include "nest/protocol.h"
#include "nest/snmp.h"
#include "conf/conf.h"
#include "lib/socket.h"

struct agentx_tcp_agent
{
	ip_addr addr;
	int port;
};

struct agentx_unix_agent
{
	char path[108];
};

typedef union agentx_agent
{
	struct agentx_tcp_agent tcp;
} agentx_agent;

typedef enum _agentx_transport
{
	AGENTX_TRANSPORT_NONE,
	AGENTX_TRANSPORT_TCP,
/*	AGENTX_TRANSPORT_UNIX*/
} agentx_transport;

struct agentx_config
{
	struct proto_config c;
	agentx_transport transport;
	agentx_agent agent;
	int timeout;
};

typedef enum _agentx_state
{
	AGENTX_STATE_DISABLED,
	AGENTX_STATE_DISCONNECTED,
	AGENTX_STATE_CONNECTING,
	AGENTX_STATE_OPEN_SENT,
	AGENTX_STATE_ESTABLISHED
} agentx_state;

struct agentx_proto
{
	struct proto p;
	struct agentx_config *cf;

	snmp_protocol snmp;

	agentx_state state;
	sock *sk; /* Valid in CONNECTING, OPEN_SENT, and ESTABLISHED states */
	u32 session_id; /* Only valid in the ESTABLISHED state */
};

#endif // _BIRD_AGENTX_H_
