/*
 *  BIRD -- AgentX Packet Processing
 *
 *  (c) 2014 Peter Christensen <pch@ordbogen.com>
 *
 *  Can be freely distributed and used under the terms of the GNU GPL.
 */

#ifndef _BIRD_AGENTX_PACKETS_H_
#define _BIRD_AGENTX_PACKETS_H_

int agentx_rx(struct birdsock *sk, int size);
void agentx_tx(struct birdsock *sk);

#endif // _BIRD_AGENTX_PACKETS_H_
