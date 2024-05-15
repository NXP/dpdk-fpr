/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */
/*
 * parts from:
 *
 * Copyright (c) 2015 Gandi S.A.S.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <rte_ether.h>
#include <netinet/in.h>
#include <linux/types.h>

#ifdef LPM6_16BIT
#define NEI_NUM_ENTRIES (1 << 16)
#else
#define NEI_NUM_ENTRIES (1 << 8)
#endif

struct nei_entry {
	struct rte_ether_addr nexthop_hwaddr;	/* 6 bytes */
	struct rte_ether_addr port_addr;	/* 6 bytes */

	uint8_t in_use;
	uint8_t valid;

//same as NUD_* defines from linux/neighbour.h, like NUD_DELAY
	uint8_t state;

#define NEI_ACTION_FWD      0x01
#define NEI_ACTION_DROP     0x02
#define NEI_ACTION_KNI      0x03
	uint8_t action;

	int16_t vlan_id;
	uint16_t port_id;

	int32_t refcnt;
};								//24bytes

//must be 16bytes aligned
struct nei_entry4 {
	struct nei_entry neighbor;

	struct in_addr addr;
	uint8_t pad[4];
};

struct nei_entry6 {
	struct nei_entry neighbor;

	struct in6_addr addr;		//16bytes
	uint8_t pad[8];
};

struct nei_table {
	union {
		struct nei_entry4 t4[NEI_NUM_ENTRIES];
		struct nei_entry6 t6[NEI_NUM_ENTRIES];
	} entries;
};

int neighbor4_lookup_nexthop(struct nei_table *, struct in_addr *nexthop,
							 uint16_t * nexthop_id, uint16_t exclude_id);
int neighbor4_add_nexthop(struct nei_table *, struct in_addr *nexthop,
						  uint16_t * nexthop_id, uint8_t action);
int neighbor4_set_nexthop(struct nei_table *, struct in_addr *nexthop,
						  uint16_t nexthop_id, uint8_t action);
int neighbor4_refcount_incr(struct nei_table *, uint16_t nexthop_id);
int neighbor4_refcount_decr(struct nei_table *, uint16_t nexthop_id);
int neighbor4_set_lladdr_port(struct nei_table *, uint16_t nexthop_id,
							  struct rte_ether_addr *port_addr,
							  struct rte_ether_addr *lladdr, int16_t port_id,
							  int16_t vlan_id);
int neighbor4_copy_lladdr_port(struct nei_table *t, uint16_t src_nexthop_id, uint16_t dst_nexthop_id);
int neighbor4_set_state(struct nei_table *, uint16_t nexthop_id, uint8_t flags);
int neighbor4_set_action(struct nei_table *t, uint16_t nexthop_id, uint8_t action);
int neighbor4_set_port(struct nei_table *t, uint16_t nexthop_id,
					   int32_t port_id);
int neighbor4_delete(struct nei_table *, uint16_t nexthop_id);

int neighbor6_lookup_nexthop(struct nei_table *, struct in6_addr *nexthop,
							 uint16_t * nexthop_id, uint16_t exclude_id);
int neighbor6_add_nexthop(struct nei_table *, struct in6_addr *nexthop,
						  uint16_t *nexthop_id, uint8_t action);
int neighbor6_set_nexthop(struct nei_table *, struct in6_addr *nexthop,
						  uint16_t nexthop_id, uint8_t action);
int neighbor6_refcount_incr(struct nei_table *, uint16_t nexthop_id);
int neighbor6_refcount_decr(struct nei_table *, uint16_t nexthop_id);
int neighbor6_set_lladdr_port(struct nei_table *, uint16_t nexthop_id,
							  struct rte_ether_addr *port_addr,
							  struct rte_ether_addr *lladdr, int16_t port_id,
							  int16_t vlan_id);
int neighbor6_copy_lladdr_port(struct nei_table *t, uint16_t src_nexthop_id, uint16_t dst_nexthop_id);
int neighbor6_set_state(struct nei_table *, uint16_t nexthop_id, uint8_t flags);
int neighbor6_set_action(struct nei_table *, uint16_t nexthop_id, uint8_t action);
int neighbor6_set_port(struct nei_table *t, uint16_t nexthop_id,
					   int32_t port_id);
int neighbor6_delete(struct nei_table *, uint16_t nexthop_id);


struct nei_table *nei_create(int socketid);
void nei_free(struct nei_table *nei);
