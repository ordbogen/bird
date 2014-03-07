/*
 *  BIRD -- Agent Extensibility Protocol
 *
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

CF_HDR

#include "proto/agentx/agentx.h"

#include <string.h>

CF_DEFINES

#define AGENTX_CFG	((struct agentx_config *)this_proto)

CF_DECLS

CF_KEYWORDS(AGENTX, AGENT, TCP, UNIX, PORT, TIMEOUT)

%type <i> agentx_port
%type <a> agentx_ip

CF_GRAMMAR

CF_ADDTO(proto, agentx_proto)

agentx_proto_start: proto_start AGENTX
{
  this_proto = proto_config_new(&proto_agentx, sizeof(struct agentx_config), $1);
  AGENTX_CFG->transport = AGENTX_TRANSPORT_NONE;
  AGENTX_CFG->timeout = 0;
};

agentx_port:
   /* empty */ { $$ = 705; }
 | PORT expr { $$ = $2; }
 ;

agentx_ip: ipa agentx_port
{
  AGENTX_CFG->transport = AGENTX_TRANSPORT_TCP;
  AGENTX_CFG->agent.tcp.addr = $1;
  AGENTX_CFG->agent.tcp.port = $2;
  
  if (AGENTX_CFG->agent.tcp.port < 1 || AGENTX_CFG->agent.tcp.port > 65535)
    cf_error("Invalid port number");
};

/*
agentx_unix: TEXT
{
	if (strlen($1) > sizeof(AGENTX_CFG->agent.unix.path))
		cf_error("Path too long");

	AGENTX_CFG->transport = AGENTX_TRANSPORT_UNIX;
	strcpy(AGENTX_CFG->agent.unix.path, $1);
};
*/

agentx_timeout: expr
{
  AGENTX_CFG->timeout = $1;
};

agentx_proto_item:
   proto_item
 | AGENT TCP agentx_ip
 /*| AGENT UNIX agentx_unix*/
 | TIMEOUT agentx_timeout
 ;

agentx_proto_opts:
   /* empty */
 | agentx_proto_opts agentx_proto_item ';'
 ;

agentx_proto: agentx_proto_start proto_name '{' agentx_proto_opts '}'
{
  if (AGENTX_CFG->transport == AGENTX_TRANSPORT_NONE)
    cf_error("Must specify an agent");
};

