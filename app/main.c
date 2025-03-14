/*
 * FPR userland router which uses DPDK for its fastpath switching
 *
 */
/*
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
/*
 * Parts from:
 *
 * Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 * * Neither the name of Intel Corporation nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2025 NXP
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <arpa/inet.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <rte_version.h>
#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_atomic.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>
#include <rte_acl.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include <libneighbour.h>
#include <libnetlink.h>

#include "common.h"
#include "routing.h"
#include "control.h"
#include "kni.h"
#include "cmdline.h"
#include "acl.h"
#include "config.h"

/* Structure to be used in hashing for NAT Masq. */
struct hash_value {
	uint32_t ip; /* IP address */
	uint16_t port; /* Port */
};

/* prepare list of free ports and pre-allocate memory for value */
uint16_t hash_return_value; /* used NAT port */

/* Preparing LIST of unused ports */
struct nat_masq_entry {
	STAILQ_ENTRY(nat_masq_entry) next;
	uint16_t key;
	struct hash_value value;
};

STAILQ_HEAD(nat_masq_entries, nat_masq_entry) nat_masq_entries;

/**
 * ICMPv6 Header
 */
struct icmpv6_hdr {
	uint8_t icmp_type;   /* ICMPv6 packet type. */
	uint8_t icmp_code;   /* ICMPv6 packet code. */
	uint16_t icmp_cksum; /* ICMPv6 packet checksum. */
	uint32_t icmp_body;  /* ICMPv6 packet body. */
} __attribute__((__packed__));

lookup_struct_t* ipv4_pktj_lookup_struct[NB_SOCKETS];
lookup6_struct_t* ipv6_pktj_lookup_struct[NB_SOCKETS];
neighbor_struct_t* neighbor4_struct[NB_SOCKETS];
neighbor_struct_t* neighbor6_struct[NB_SOCKETS];

#define RATE_LIMITED UINT8_MAX
uint8_t rlimit4_lookup_table[NB_SOCKETS]
			    [MAX_RLIMIT_RANGE_NET] __rte_cache_aligned;
struct rlimit6_data rlimit6_lookup_table[NB_SOCKETS][NEI_NUM_ENTRIES];
uint32_t rlimit4_max[NB_SOCKETS][MAX_RLIMIT_RANGE]
		    [MAX_RLIMIT_RANGE_HOST] __rte_cache_aligned;
uint32_t rlimit6_max[NB_SOCKETS][NEI_NUM_ENTRIES] __rte_cache_aligned;

struct control_params_t {
	void* addr;
	int lcore_id;
};
struct control_params_t control_handle4[NB_SOCKETS];
struct control_params_t control_handle6[NB_SOCKETS];

#define MAX_HASH_ENTRIES (1 << 19)

#define PKTJ_PKT_TYPE(m) (m)->packet_type
#define PKTJ_IP_MASK (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)
#define PKTJ_IPV4_MASK RTE_PTYPE_L3_IPV4
#define PKTJ_IPV6_MASK RTE_PTYPE_L3_IPV6

#define ETHER_TYPE_BE_IPv4 0x0008
#define ETHER_TYPE_BE_IPv6 0xDD86
#define ETHER_TYPE_BE_VLAN 0x0081
#define ETHER_TYPE_BE_ARP 0x0608

#define PKTJ_TEST_IPV4_HDR(m) RTE_ETH_IS_IPV4_HDR((m)->packet_type)
#define PKTJ_TEST_IPV6_HDR(m) RTE_ETH_IS_IPV6_HDR((m)->packet_type)
#define PKTJ_TEST_ARP_HDR(m) ((m)->packet_type & RTE_PTYPE_L2_ETHER_ARP)

#ifndef IPv6_BYTES
#define IPv6_BYTES_FMT                         \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
	"%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define IPv6_BYTES(addr)                                                       \
	addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6],         \
	    addr[7], addr[8], addr[9], addr[10], addr[11], addr[12], addr[13], \
	    addr[14], addr[15]
#endif

#define MEMPOOL_CACHE_SIZE 256

/*
 * This expression is used to calculate the number of mbufs needed depending on
 * user input, taking
 *  into account memory for rx and tx hardware rings, cache per lcore and mtable
 * per port per lcore.
 *  RTE_MAX is used to ensure that NB_MBUF never goes below a minimum value of
 * 8192
 */

#define NB_MBUF                                                      \
	RTE_MAX((nb_ports * nb_rx_queue * RTE_TEST_RX_DESC_DEFAULT + \
		 nb_ports * nb_lcores * MAX_PKT_BURST +              \
		 nb_ports * nb_tx_queue * RTE_TEST_TX_DESC_DEFAULT + \
		 nb_lcores * MEMPOOL_CACHE_SIZE),                    \
		(unsigned)8192)

#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define MAX_TX_BURST (MAX_PKT_BURST / 2)

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET 3

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/* ethernet addresses of ports */
struct rte_ether_addr ports_eth_addr[RTE_MAX_ETHPORTS];

/* replace first 12B of the ethernet header. */
#define MASK_ETH 0x3f

static struct rte_mempool* pktmbuf_pool[NB_SOCKETS];
static uint64_t glob_tsc[RTE_MAX_LCORE];
static struct rte_mempool* knimbuf_pool[RTE_MAX_ETHPORTS];
struct nei_entry kni_neighbor[RTE_MAX_ETHPORTS];

#define IPV4_L3FWD_LPM_MAX_RULES (1 << 20) // 1048576
#define IPV4_L3FWD_LPM_NUMBER_TBL8S (1 << 16)
#define IPV6_L3FWD_LPM_MAX_RULES (1 << 19) // 524288
#define IPV6_L3FWD_LPM_NUMBER_TBL8S (1 << 16)

struct lcore_stats stats[RTE_MAX_LCORE];

struct lcore_conf lcore_conf[RTE_MAX_LCORE];
static rte_atomic32_t main_loop_stop = RTE_ATOMIC32_INIT(0);

static void
print_ethaddr(const char* name, const struct rte_ether_addr* eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s\n", name, buf);
}

/* Send burst of packets on an output interface */
static inline int
send_burst(struct lcore_conf* qconf, uint16_t n, uint8_t port)
{
	struct rte_mbuf** m_table;
	int ret;
	uint16_t queueid;

	queueid = qconf->tx_queue_id[port];
	m_table = (struct rte_mbuf**)qconf->tx_mbufs[port].m_table;

	ret = rte_eth_tx_burst(port, queueid, m_table, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m_table[ret]);
		} while (++ret < n);
	}

	return 0;
}

static inline uint32_t
get_ipv4_dst_port(void *ipv4_hdr, uint8_t portid,
		  lookup_struct_t *ipv4_pktj_lookup_struct)
{
	uint32_t next_hop;

	return
	    (rte_lpm_lookup(
		 ipv4_pktj_lookup_struct,
		 rte_be_to_cpu_32(((struct rte_ipv4_hdr*)ipv4_hdr)->dst_addr),
		 &next_hop) == 0)
		? next_hop
		: portid;
}

static inline uint16_t
get_ipv6_dst_port(void *ipv6_hdr, uint8_t portid,
		  lookup6_struct_t *ipv6_pktj_lookup_struct)
{
	lpm6_neigh next_hop;
	return (rte_lpm6_lookup(ipv6_pktj_lookup_struct,
			     ((struct rte_ipv6_hdr *)ipv6_hdr)->dst_addr,
			     &next_hop) == 0)
		? next_hop
		: portid;
}

static inline __attribute__((always_inline)) uint16_t
get_dst_port(const struct lcore_conf* qconf,
	     struct rte_mbuf* pkt,
	     uint32_t dst_ipv4,
	     struct nei_entry* kni_neighbor)
{
	uint32_t next_hop;
	lpm6_neigh next_hop6;
	struct rte_ipv6_hdr *ipv6_hdr;
	struct rte_ether_hdr *eth_hdr;

	if (PKTJ_TEST_IPV4_HDR(pkt)) {
		if (rte_lpm_lookup(qconf->ipv4_lookup_struct, dst_ipv4,
				   &next_hop) != 0)
			next_hop = 0;
	} else if (PKTJ_TEST_IPV6_HDR(pkt)) {
		eth_hdr = rte_pktmbuf_mtod(pkt, struct rte_ether_hdr*);
		ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr + 1);
		if (rte_lpm6_lookup(qconf->ipv6_lookup_struct,
				    ipv6_hdr->dst_addr, &next_hop6) != 0)
			next_hop6 = 0;
        return next_hop6;
	} else {
		next_hop = kni_neighbor->port_id;
	}

	return (uint16_t) next_hop;
}

static inline int
rate_limit_step_ipv4(struct lcore_conf* qconf,
		     struct rte_mbuf* pkt,
		     unsigned lcore_id)
{
	struct rte_ipv4_hdr* ipv4_hdr;
	uint8_t range_id;
	union rlimit_addr* dst_addr;
	uint32_t naddr;

	ipv4_hdr = rte_pktmbuf_mtod_offset(pkt, struct rte_ipv4_hdr*,
					   sizeof(struct rte_ether_hdr));
	naddr = rte_be_to_cpu_32(ipv4_hdr->dst_addr);
	dst_addr = (union rlimit_addr *)&naddr;
	range_id = rlimit4_lookup_table[rte_lcore_to_socket_id(lcore_id)]
				       [dst_addr->network];
	// check if the dest cidr range is in the lookup table
	if (range_id != INVALID_RLIMIT_RANGE) {
		// increase the counter for this dest
		// and check against the max value
		if (qconf->rlimit4_cur[range_id][dst_addr->host]++ >=
		    rlimit4_max[rte_lcore_to_socket_id(lcore_id)][range_id]
			       [dst_addr->host]) {
			return RATE_LIMITED;
		}
	}

	return 0;
}

static inline int
rate_limit_step_ipv6(struct lcore_conf* qconf,
		     uint16_t dst_port,
		     unsigned lcore_id)
{
	// increase the packet counter for this neighbor
	// and check against the max value
	if (qconf->rlimit6_cur[dst_port]++ >=
	    rlimit6_max[rte_lcore_to_socket_id(lcore_id)][dst_port]) {
		return RATE_LIMITED;
	}

	return 0;
}

/*
 * Put one packet in acl_search struct according to the packet ol_flags
 */
static inline void
prepare_one_packet(struct rte_mbuf** pkts_in,
		   struct acl_search_t* acl,
		   int index)
{
	struct rte_mbuf* pkt = pkts_in[index];

	// XXX we cannot filter non IP packet yet
	if (PKTJ_TEST_IPV4_HDR(pkt)) {
		/* Fill acl structure */
		acl->data_ipv4[acl->num_ipv4] = MBUF_IPV4_2PROTO(pkt);
		acl->m_ipv4[(acl->num_ipv4)++] = pkt;
	} else if (PKTJ_TEST_IPV6_HDR(pkt)) {
		/* Fill acl structure */
		acl->data_ipv6[acl->num_ipv6] = MBUF_IPV6_2PROTO(pkt);
		acl->m_ipv6[(acl->num_ipv6)++] = pkt;
	}
}

/*
 * Loop through all packets and classify them if acl_search if possible.
 */
static inline void
prepare_acl_parameter(struct rte_mbuf** pkts_in,
		      struct acl_search_t* acl,
		      int nb_rx)
{
	int i = 0, j = 0;

	acl->num_ipv4 = 0;
	acl->num_ipv6 = 0;

#define PREFETCH()                                          \
	rte_prefetch0(rte_pktmbuf_mtod(pkts_in[i], void*)); \
	i++;                                                \
	j++;

	// we prefetch0 packets 3 per 3
	switch (nb_rx % PREFETCH_OFFSET) {
		while (nb_rx != i) {
		case 0:
			PREFETCH();
		case 2:
			PREFETCH();
		case 1:
			PREFETCH();

			while (j > 0) {
				prepare_one_packet(pkts_in, acl, i - j);
				--j;
			}
		}
	}
}

/*
 * Take both acl from acl_search and filters packets related to those acl.
 * Put back unfiltered packets in pkt_burst without overwriting non IP packets.
 */
static inline int
filter_packets(uint32_t lcore_id,
	       struct rte_mbuf** pkts,
	       struct acl_search_t* acl_search,
	       int nb_rx,
	       struct rte_acl_ctx* acl4,
	       struct rte_acl_ctx* acl6)
{
	uint32_t* res;
	struct rte_mbuf** acl_pkts;
	int nb_res;
	int i;
	int nb_pkts = 0;  // number of packet in the newly crafted pkts

	nb_res = acl_search->num_ipv4;
	res = acl_search->res_ipv4;
	acl_pkts = acl_search->m_ipv4;

	// TODO maybe we want to manually unroll those loops
	// TODO maye we could replace those loops by an inlined fonction

	// if num_ipv4 is equal to zero we skip it
	for (i = 0; i < nb_res; ++i) {
		// if the packet must be filtered, free it and don't add it back
		// in pkts
		if (unlikely(acl4 != NULL &&
			     (res[i] & ACL_DENY_SIGNATURE) != 0)) {
/* in the ACL list, drop it */
#ifdef L3FWDACL_DEBUG
			dump_acl4_rule(acl_pkts[i], res[i]);
#endif
			stats[lcore_id].nb_acl_dropped++;
			rte_pktmbuf_free(acl_pkts[i]);
		} else {
			// add back the unfiltered packet in pkts but don't
			// discard non IP packet
			while (nb_pkts < nb_rx &&
			       !(PKTJ_PKT_TYPE(pkts[nb_pkts]) & PKTJ_IP_MASK)) {
				nb_pkts++;
			}
			pkts[nb_pkts++] = acl_pkts[i];
		}
	}

	nb_res = acl_search->num_ipv6;
	res = acl_search->res_ipv6;
	acl_pkts = acl_search->m_ipv6;

	// if num_ipv6 is equal to zero we skip it
	for (i = 0; i < nb_res; ++i) {
		// if the packet must be filtered, free it and don't add it back
		// in pkts
		if (unlikely(acl6 != NULL &&
			     (res[i] & ACL_DENY_SIGNATURE) != 0)) {
/* in the ACL list, drop it */
#ifdef L3FWDACL_DEBUG
			dump_acl6_rule(acl_pkts[i], res[i]);
#endif
			stats[lcore_id].nb_acl_dropped++;
			rte_pktmbuf_free(acl_pkts[i]);
		} else {
			// add back the unfiltered packet in pkts but don't
			// discard non IP packet
			while (nb_pkts < nb_rx &&
			       !(PKTJ_PKT_TYPE(pkts[nb_pkts]) & PKTJ_IP_MASK)) {
				nb_pkts++;
			}
			pkts[nb_pkts++] = acl_pkts[i];
		}
	}

	// add back non IP packet that are after nb_pkts packets
	for (i = nb_pkts; i < nb_rx; i++) {
		if (!(PKTJ_PKT_TYPE(pkts[i]) & PKTJ_IP_MASK)) {
			pkts[nb_pkts++] = pkts[i];
		}
	}

	return nb_pkts;
}

#ifdef ATOMIC_ACL
static inline int
rte_atomic64_cmpswap(volatile uintptr_t* dst, uintptr_t* exp, uintptr_t src)
{
	uint8_t res;

	asm volatile(MPLOCKED
		     "cmpxchgq %[src], %[dst];"
		     "movq %%rax, %[exp];"
		     "sete %[res];"
		     : [res] "=a"(res), /* output */
		       [dst] "=m"(*dst), [exp] "=m"(*exp)
		     : [src] "r"(src), /* input */
		       "a"(*exp), "m"(*dst)
		     : "memory", "cc"); /* no-clobber list */
	return res;
}
#endif

/* main processing loop */
static int
main_loop(__rte_unused void* dummy)
{
	struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
	uint32_t lcore_id;
	uint64_t prev_tsc, diff_tsc, cur_tsc, rate_tsc = 0;
	int i, j, nb_rx;
	uint8_t portid = 0, queueid;
	struct lcore_conf* qconf;
	const uint64_t drain_tsc =
	    (rte_get_tsc_hz() + US_PER_S - 1) / US_PER_S * BURST_TX_DRAIN_US;
	const uint64_t ticks_per_s = rte_get_tsc_hz();
	int32_t f_stop;
	char thread_name[16];
#ifdef ATOMIC_ACL
	struct rte_acl_ctx* acx;
#endif

	prev_tsc = 0;

	lcore_id = rte_lcore_id();
	qconf = &lcore_conf[lcore_id];

	/* Set thread name */
	snprintf(thread_name, 16, "forward-%u", lcore_id);
	rte_thread_setname(pthread_self(), thread_name);

	if (qconf->n_rx_queue == 0) {
		RTE_LOG(INFO, PKTJ1, "lcore %u has nothing to do\n", lcore_id);
		return 0;
	}

	RTE_LOG(INFO, PKTJ1, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_queue; i++) {
		portid = qconf->rx_queue_list[i].port_id;
		stats[lcore_id].port_id = portid;
		queueid = qconf->rx_queue_list[i].queue_id;
		RTE_LOG(INFO, PKTJ1,
			" -- lcoreid=%u portid=%hhu rxqueueid=%hhu\n", lcore_id,
			portid, queueid);
	}

	while (1) {
		f_stop = rte_atomic32_read(&main_loop_stop);
		if (unlikely(f_stop))
			break;
		stats[lcore_id].nb_iteration_looped++;
		cur_tsc = glob_tsc[lcore_id];

#ifdef ATOMIC_ACL
#define SWAP_ACX(cur_acx, new_acx)                                            \
	acx = cur_acx;                                                        \
	if (!rte_atomic64_cmpswap((uintptr_t*)&new_acx, (uintptr_t*)&cur_acx, \
				  (uintptr_t)new_acx)) {                      \
		rte_acl_free(acx);                                            \
	}
#else
#define SWAP_ACX(cur_acx, new_acx)          \
	if (unlikely(cur_acx != new_acx)) { \
		rte_acl_free(cur_acx);      \
		cur_acx = new_acx;          \
	}
#endif

		SWAP_ACX(qconf->cur_acx_ipv4, qconf->new_acx_ipv4);
		SWAP_ACX(qconf->cur_acx_ipv6, qconf->new_acx_ipv6);
#undef SWAP_ACX

		/*
		 * TX burst queue drain
		 */
		diff_tsc = cur_tsc - prev_tsc;
		if (unlikely(diff_tsc > drain_tsc)) {
			/*
			 * This could be optimized (use queueid instead of
			 * portid), but it is not called so often
			 */
			for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
				if (qconf->tx_mbufs[portid].len == 0)
					continue;
				send_burst(qconf, qconf->tx_mbufs[portid].len,
					   portid);
				qconf->tx_mbufs[portid].len = 0;
			}

			uint64_t sec = cur_tsc / ticks_per_s;
			if (sec > rate_tsc) {
				rate_tsc = sec;

				// reset rate limit counters
				qconf->kni_rate_limit_cur = 0;

				memset(qconf->rlimit6_cur, 0,
				       sizeof(qconf->rlimit6_cur));
				memset(qconf->rlimit4_cur, 0,
				       sizeof(qconf->rlimit4_cur));
			}

			prev_tsc = cur_tsc;
		}

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_queue; ++i) {
			portid = qconf->rx_queue_list[i].port_id;
			queueid = qconf->rx_queue_list[i].queue_id;
			nb_rx = rte_eth_rx_burst(portid, queueid, pkts_burst,
						 MAX_PKT_BURST);
			if (unlikely(nb_rx == 0))
				continue;

			RTE_LOG(DEBUG, PKTJ1,
				"main_loop nb_rx %d  queue_id %d\n", nb_rx,
				queueid);
			stats[lcore_id].nb_rx += nb_rx;
			{
				struct acl_search_t acl_search;

				prepare_acl_parameter(pkts_burst, &acl_search,
						      nb_rx);

				if (likely(qconf->cur_acx_ipv4 &&
					   acl_search.num_ipv4)) {
					rte_acl_classify(
					    qconf->cur_acx_ipv4,
					    acl_search.data_ipv4,
					    acl_search.res_ipv4,
					    acl_search.num_ipv4,
					    DEFAULT_MAX_CATEGORIES);
				}

				if (likely(qconf->cur_acx_ipv6 &&
					   acl_search.num_ipv6)) {
					rte_acl_classify(
					    qconf->cur_acx_ipv6,
					    acl_search.data_ipv6,
					    acl_search.res_ipv6,
					    acl_search.num_ipv6,
					    DEFAULT_MAX_CATEGORIES);
				}
				nb_rx = filter_packets(
				    lcore_id, pkts_burst, &acl_search, nb_rx,
				    qconf->cur_acx_ipv4, qconf->cur_acx_ipv6);
			}
			if (unlikely(nb_rx == 0))
				continue;

			RTE_LOG(DEBUG, PKTJ1,
				"main_loop acl nb_rx %d  queue_id %d\n", nb_rx,
				queueid);

			for (j = 0; j < nb_rx; j++) {
				int ret;
				uint16_t pn;
				int rate = 0;
				struct rte_ether_hdr* eth_hdr;
				struct nei_entry* entries;
				struct rte_ipv6_hdr *ipv6_hdr = NULL;
				struct rte_ipv4_hdr* ipv4_hdr = NULL;

       				eth_hdr = rte_pktmbuf_mtod(pkts_burst[j], struct rte_ether_hdr*);

				/* Support for IPv4 only */
        			if (likely(PKTJ_TEST_IPV4_HDR(pkts_burst[j]))) {
                			ipv4_hdr = (struct rte_ipv4_hdr*)(eth_hdr + 1);
					/* If nat masqurade and only udp */
					if (kni_port_params_array[portid]->masq &&
							ipv4_hdr->next_proto_id == IPPROTO_UDP) {
						struct rte_udp_hdr *udp;
						struct hash_value *results;

						udp = (struct rte_udp_hdr *)(ipv4_hdr + 1);

						ret = rte_hash_lookup_data(kni_port_params_array[portid]->hash,
								(const void *)&udp->dst_port, (void **)&results);
						if (!ret) {
							RTE_LOG(DEBUG, PKTJ1, "NAT lookup found IP = 0x%x, port = %d\n",
									(uint32_t)results->ip, results->port);
							udp->dst_port = results->port;
							ipv4_hdr->dst_addr = results->ip;
						} else {
							RTE_LOG(DEBUG, PKTJ1, "No NAT entry found for UDP port = %d\n",
									rte_be_to_cpu_16(udp->dst_port));
						}
					}

				    	rate = rate_limit_step_ipv4(qconf, pkts_burst[j], lcore_id);
					if (unlikely(rate == RATE_LIMITED)) {
						rte_pktmbuf_free(pkts_burst[j]);
						stats[lcore_id].nb_ratel_dropped++;
						continue;
					}
					pn = get_ipv4_dst_port(ipv4_hdr, 0, qconf->ipv4_lookup_struct);
					entries = &qconf->neighbor4_struct->entries.t4[pn].neighbor;
				} else if (PKTJ_TEST_IPV6_HDR(pkts_burst[j])) {

                			ipv6_hdr = (struct rte_ipv6_hdr*)(eth_hdr + 1);
				    	
					pn = get_ipv6_dst_port(ipv6_hdr, 0, qconf->ipv6_lookup_struct);
					rate = rate_limit_step_ipv6(qconf, pn, lcore_id);
					if (unlikely(rate == RATE_LIMITED)) {
						rte_pktmbuf_free(pkts_burst[j]);
						stats[lcore_id].nb_ratel_dropped++;
						continue;
					}
					entries = &qconf->neighbor6_struct->entries.t6[pn].neighbor;
				} else {
					if (!PKTJ_TEST_ARP_HDR(pkts_burst[j])) {
						if (++qconf->kni_rate_limit_cur > kni_rate_limit) {
							RTE_LOG(DEBUG, PKTJ1, "Dropping kni rate limit packets\n");
							stats[lcore_id].nb_ratel_dropped++;
							rte_pktmbuf_free(pkts_burst[j]);
							continue;
						}
					}
					pn = kni_port_params_array[portid]->port_id;
					RTE_LOG(DEBUG, PKTJ1, "Not an IPv4 packet, send it to tap %d\n", pn);
					ret = rte_eth_tx_burst(pn, qconf->tx_queue_id[pn],
							&pkts_burst[j], 1);
					if (!ret) {
						RTE_LOG(ERR, PKTJ1,"failed to send\n");
						stats[lcore_id].nb_kni_dropped++;
						rte_pktmbuf_free(pkts_burst[j]);
					}
					stats[lcore_id].nb_kni_tx++;
					continue;
				}
				if (entries->in_use != 1 || entries->valid !=1 || entries->action !=1 ) {
					if (++qconf->kni_rate_limit_cur > kni_rate_limit) {
						RTE_LOG(DEBUG, PKTJ1, "Dropping kni rate limit packets\n");
						stats[lcore_id].nb_ratel_dropped++;
						rte_pktmbuf_free(pkts_burst[j]);
						continue;
					}
	
				 	char buf_eth[RTE_ETHER_ADDR_FMT_SIZE];
				 	char buf_eth1[RTE_ETHER_ADDR_FMT_SIZE];
					rte_ether_format_addr(buf_eth, sizeof(buf_eth),
							&entries->nexthop_hwaddr);
					rte_ether_format_addr(
							buf_eth1, sizeof(buf_eth1), &entries->port_addr);
					RTE_LOG(DEBUG, PKTJ1, "Not valid Neigh entry: Idx = %d Nhop %s paddr = %s, inuse = %d,"
							" valid = %d, state = %d action =%d,"
							"port_id = %d refcount = %d, vlan_id = %d\n", pn, buf_eth, buf_eth1, entries->in_use,
							entries->valid,  entries->state,  entries->action,  entries->port_id,
							entries->refcnt,  entries->vlan_id);
					/* Changing to KNI */
					entries->port_id = kni_port_params_array[portid]->port_id;
					RTE_LOG(DEBUG, PKTJ1, "Submitting to KNI = %d\n", entries->port_id);
				  	ret = rte_eth_tx_burst(entries->port_id, qconf->tx_queue_id[entries->port_id],
							&pkts_burst[j], 1);
				  	if (ret == 0) {
						stats[lcore_id].nb_kni_dropped++;
						RTE_LOG(ERR, PKTJ1, "Failed to TX packet, free it\n");
				  		rte_pktmbuf_free(pkts_burst[j]);
				  	}
					stats[lcore_id].nb_kni_tx++;
				  } else {
					/* Update packet info */
					rte_ether_addr_copy(&entries->port_addr,
						&eth_hdr->src_addr);
					rte_ether_addr_copy(&entries->nexthop_hwaddr,
							&eth_hdr->dst_addr);
					/* If NAT masquerade and only udp */
					if (kni_port_params_array[entries->port_id]->masq &&
							ipv4_hdr->next_proto_id == IPPROTO_UDP) {
						struct rte_udp_hdr *udp;
						uint16_t *used_port;
						struct hash_value val;

						val.ip = ipv4_hdr->src_addr;

						udp = (struct rte_udp_hdr *)(ipv4_hdr + 1);
						val.port = udp->src_port;
						ret = rte_hash_lookup_data(kni_port_params_array[entries->port_id]->reply_hash,
								(const void *)&val, (void **)&used_port);
						if (ret) {
							struct nat_masq_entry *entry;

							assert(!STAILQ_EMPTY(&nat_masq_entries));
							entry = STAILQ_FIRST(&nat_masq_entries);
							assert(entry != NULL);
							STAILQ_REMOVE_HEAD(&nat_masq_entries, next);
							entry->value.ip = val.ip;
							entry->value.port = val.port;
							RTE_LOG(DEBUG, PKTJ1, "No NAT entry found, so adding\n");
							ret = rte_hash_add_key_data(kni_port_params_array[entries->port_id]->hash,
									(const void *)&entry->key, &entry->value);
							if (ret) {
								RTE_LOG(ERR, PKTJ1, "Failed to add NAT for IP 0x%x port %d\n", val.ip, val.port);
							}
							hash_return_value = entry->key;
							ret = rte_hash_add_key_data(kni_port_params_array[entries->port_id]->reply_hash,
									(const void *)&entry->value, &hash_return_value);
							if (ret) {
								 RTE_LOG(ERR, PKTJ1, "Failed to add reply NAT\n");
							}
							udp->src_port = entry->key;
						} else {
							RTE_LOG(DEBUG, PKTJ1, "Already added NAT port = %d\n", (uint32_t)*used_port);
							udp->src_port = *used_port;
							/* Hash Entry to be updated for timestamp */
						}
						ipv4_hdr->src_addr = kni_port_params_array[entries->port_id]->addr.s_addr;
					}
					if (likely(PKTJ_TEST_IPV4_HDR(pkts_burst[j])) && ipv4_hdr != NULL) {
						--(ipv4_hdr->time_to_live);
                                        	++(ipv4_hdr->hdr_checksum);
					} else if (PKTJ_TEST_IPV6_HDR(pkts_burst[j]) && ipv6_hdr != NULL) {
						ipv6_hdr->hop_limits--;
					}
					if (kni_port_params_array[entries->port_id]->masq) {
						/* Offloading checksum */
						pkts_burst[j]->ol_flags |= (RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM);
						pkts_burst[j]->l2_len = sizeof(*eth_hdr);
						pkts_burst[j]->l3_len = sizeof(*ipv4_hdr);
					}
				  	ret = rte_eth_tx_burst(entries->port_id, qconf->tx_queue_id[entries->port_id],
							&pkts_burst[j], 1);
				  	if (ret == 0) {
						stats[lcore_id].nb_dropped++;
						RTE_LOG(DEBUG, PKTJ1, "Failed to TX packet, free it\n");
				  		rte_pktmbuf_free(pkts_burst[j]);
				  	}
					stats[lcore_id].nb_tx++;
				 }

			}
		}
	}
	return 0;
}

static int
check_lcore_params(void)
{
	uint8_t queue, lcore;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
			RTE_LOG(ERR, PKTJ1, "invalid queue number: %hhu\n",
				queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			RTE_LOG(
			    ERR, PKTJ1,
			    "error: lcore %hhu is not enabled in lcore mask\n",
			    lcore);
			return -1;
		}
	}
	return 0;
}

static int
check_port_config(const unsigned nb_ports)
{
	unsigned portid;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		portid = lcore_params[i].port_id;
		if ((enabled_port_mask & (1 << portid)) == 0) {
			RTE_LOG(ERR, PKTJ1,
				"port %u is not enabled in port mask\n",
				portid);
			return -1;
		}
		if (portid >= nb_ports) {
			RTE_LOG(ERR, PKTJ1,
				"port %u is not present on the board\n",
				portid);
			return -1;
		}
	}
	return 0;
}

static uint8_t
get_ports_n_rx_queues(void)
{
	uint8_t nb_queue = 0;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (enabled_port_mask & 1 << lcore_params[i].port_id)
			nb_queue++;
	}
	return nb_queue;
}

uint8_t
get_port_n_rx_queues(uint8_t port)
{
	int nb_queue = 0;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port)
			nb_queue++;
	}
	return nb_queue;
}

static int
init_lcore_rx_queues(void)
{
	uint16_t i, nb_rx_queue;
	uint8_t lcore;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			RTE_LOG(ERR, PKTJ1,
				"error: too many queues (%u) for lcore: %u\n",
				(unsigned)nb_rx_queue + 1, (unsigned)lcore);
			return -1;
		} else {
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].port_id =
			    lcore_params[i].port_id;
			lcore_conf[lcore].rx_queue_list[nb_rx_queue].queue_id =
			    lcore_params[i].queue_id;
			lcore_conf[lcore].n_rx_queue++;
		}
	}
	return 0;
}

static void
setup_lpm(int socketid)
{
	struct rte_lpm6_config config6;
	struct rte_lpm_config config4;
	char s[64];

	/* create the LPM table */
	snprintf(s, sizeof(s), "IPV4_L3FWD_LPM_%d", socketid);

	config4.max_rules = IPV4_L3FWD_LPM_MAX_RULES;
	config4.number_tbl8s = IPV4_L3FWD_LPM_NUMBER_TBL8S;
	config4.flags = 0;

	ipv4_pktj_lookup_struct[socketid] =
	    rte_lpm_create(s, socketid, &config4);
	if (ipv4_pktj_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			 "Unable to create the pktj LPM table"
			 " on socket %d\n",
			 socketid);

	/* create the LPM6 table */
	snprintf(s, sizeof(s), "IPV6_L3FWD_LPM_%d", socketid);

	config6.max_rules = IPV6_L3FWD_LPM_MAX_RULES;
	config6.number_tbl8s = IPV6_L3FWD_LPM_NUMBER_TBL8S;
	config6.flags = 0;
	ipv6_pktj_lookup_struct[socketid] =
	    rte_lpm6_create(s, socketid, &config6);
	if (ipv6_pktj_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE,
			 "Unable to create the pktj LPM6 table"
			 " on socket %d\n",
			 socketid);
}

static int
init_mem(void)
{
	struct lcore_conf* qconf;
	int socketid;
	unsigned lcore_id;
	uint8_t port;
	char s[64];
	size_t nb_mbuf;
	uint32_t nb_lcores;
	uint8_t nb_tx_queue;
	uint8_t nb_rx_queue;

	nb_lcores = rte_lcore_count();
	nb_rx_queue = get_ports_n_rx_queues();
	nb_tx_queue = nb_rx_queue;
	nb_mbuf = NB_MBUF;

	memset(&kni_neighbor, 0, sizeof(kni_neighbor));

	for (port = 0; port < RTE_MAX_ETHPORTS; port++) {
		kni_neighbor[port].in_use = 1;
		kni_neighbor[port].action = NEI_ACTION_KNI;
		kni_neighbor[port].port_id = port;
	}

	memset(rlimit4_max, UINT32_MAX, sizeof(rlimit4_max));
	memset(rlimit6_max, UINT32_MAX, sizeof(rlimit6_max));
	memset(rlimit4_lookup_table, INVALID_RLIMIT_RANGE,
	       sizeof(rlimit4_lookup_table));

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;

		socketid = 0;

		if (socketid >= NB_SOCKETS) {
			rte_exit(EXIT_FAILURE,
				 "Socket %d of lcore %u is out of range %d\n",
				 socketid, lcore_id, NB_SOCKETS);
		}
		if (pktmbuf_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "mbuf_pool_%d", socketid);
			pktmbuf_pool[socketid] = rte_pktmbuf_pool_create(
			    s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
				RTE_MBUF_DEFAULT_BUF_SIZE,
			    socketid);
			if (pktmbuf_pool[socketid] == NULL)
				rte_exit(EXIT_FAILURE,
					 "Cannot init mbuf pool on socket %d\n",
					 socketid);
			else
				RTE_LOG(INFO, PKTJ1,
					"Allocated mbuf pool on socket %d\n",
					socketid);

			setup_lpm(socketid);
		}
		if (knimbuf_pool[socketid] == NULL) {
			snprintf(s, sizeof(s), "knimbuf_pool_%d", socketid);
			knimbuf_pool[socketid] = rte_pktmbuf_pool_create(
			    s, nb_mbuf, MEMPOOL_CACHE_SIZE, 0,
				RTE_MBUF_DEFAULT_BUF_SIZE,
			    socketid);
			if (knimbuf_pool[socketid] == NULL)
				rte_exit(
				    EXIT_FAILURE,
				    "Cannot init kni mbuf pool on socket %d\n",
				    socketid);
			else
				RTE_LOG(
				    INFO, PKTJ1,
				    "Allocated kni mbuf pool on socket %d\n",
				    socketid);
		}
		qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct = ipv4_pktj_lookup_struct[socketid];
		qconf->neighbor4_struct = neighbor4_struct[socketid];
		qconf->ipv6_lookup_struct = ipv6_pktj_lookup_struct[socketid];
		qconf->neighbor6_struct = neighbor6_struct[socketid];
		qconf->cur_acx_ipv4 = ipv4_acx[socketid];
		qconf->cur_acx_ipv6 = ipv6_acx[socketid];

		memset(qconf->rlimit6_cur, 0, sizeof(qconf->rlimit6_cur));
		memset(qconf->rlimit4_cur, 0, sizeof(qconf->rlimit4_cur));
	}
	return 0;
}

/* Check the link status of all ports in up to 9s, and print them finally */
static void
check_all_ports_link_status(uint8_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 90  /* 9s (90 * 100ms) in total */
	uint8_t portid, count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;

	RTE_LOG(INFO, PKTJ1, "\nChecking link status\n");
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status)
					RTE_LOG(INFO, PKTJ1,
						"Port %d Link Up - speed %u "
						"Mbps - %s\n",
						(uint8_t)portid,
						(unsigned)link.link_speed,
						(link.link_duplex ==
						 RTE_ETH_LINK_FULL_DUPLEX)
						    ? ("full-duplex")
						    : ("half-duplex\n"));
				else
					RTE_LOG(INFO, PKTJ1,
						"Port %d Link Down\n",
						(uint8_t)portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == 0) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			RTE_LOG(INFO, PKTJ1, ".");
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1)) {
			print_flag = 1;
			RTE_LOG(INFO, PKTJ1, "done\n");
		}
	}
}

static void
init_port_tap(uint8_t portid, uint8_t q_id)
{
	struct rte_eth_txconf* txconf;
	struct rte_eth_dev_info dev_info;
	uint8_t nb_tx_queue;// queue;
	uint8_t nb_rx_queue, socketid;
	int ret;

	/* skip ports that are not enabled */
	if ((enabled_kni_port_mask & (1 << portid)) == 0) {
		RTE_LOG(INFO, PKTJ1, "\nSkipping disabled KNI port %d\n", portid);
		return;
	}

	/* init port */
	RTE_LOG(INFO, PKTJ1, "Initializing kernel port %d ...\n", portid);

	nb_rx_queue = q_id + 1;
	nb_tx_queue = nb_rx_queue;
	RTE_LOG(INFO, PKTJ1, "Creating queues: nb_rxq=%d nb_txq=%u...\n",
		nb_rx_queue, nb_tx_queue);

	ret =
	    rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot configure device: err=%d, port=%u\n", ret,
			 portid);

	/*
	 * prepare dst and src MACs for each port.
	 */
	rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	print_ethaddr(" Address:", &ports_eth_addr[portid]);

	rte_eth_dev_info_get(portid, &dev_info);
	txconf = &dev_info.default_txconf;

	socketid = 0;
	ret = rte_eth_tx_queue_setup(portid, nb_tx_queue - 1, nb_txd, socketid,
				     txconf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_tx_queue_setup: err=%d, "
			 "port=%u\n",
			 ret, portid);

	ret = rte_eth_rx_queue_setup(portid, nb_rx_queue -1, nb_rxd,
				     0, NULL,
				     knimbuf_pool[socketid]);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "rte_eth_rx_queue_setup: err=%d,"
			 "port=%u\n",
			 ret, portid);
	RTE_LOG(
	    INFO, PKTJ1,
	    "\nInitializing KNI rx/tx queues on lcore 0 for port %u ...\n",
	     portid);
}



static void
init_port(uint8_t portid)
{
	struct rte_eth_txconf* txconf;
	struct rte_eth_dev_info dev_info;
	struct lcore_conf* qconf;
	uint8_t nb_tx_queue, queue;
	uint8_t nb_rx_queue, socketid;
	int ret;
	int16_t queueid;
	unsigned lcore_id;

	/* skip ports that are not enabled */
	if ((enabled_port_mask & (1 << portid)) == 0) {
		RTE_LOG(INFO, PKTJ1, "\nSkipping disabled port %d\n", portid);
		return;
	}
	/* init port */
	RTE_LOG(INFO, PKTJ1, "Initializing port %d ...\n", portid);

	rte_eth_dev_info_get(portid, &dev_info);
	nb_rx_queue = get_port_n_rx_queues(portid);
	if (nb_rx_queue > dev_info.max_rx_queues)
		rte_exit(EXIT_FAILURE, "No enough queues %d, requested= %d\n",
				dev_info.max_rx_queues, nb_rx_queue);

	/* creating an additional TX queue for kni thread */
	if (dev_info.max_tx_queues >= (nb_rx_queue + 1)) {
		nb_tx_queue = nb_rx_queue + 1;
		kni_port_params_array[portid]->eth_tx_q_id = nb_tx_queue - 1;
		RTE_LOG(DEBUG, PKTJ1, "INFO: creating separate TX queue for KNI\n");
	} else {
		nb_tx_queue = nb_rx_queue;
		kni_port_params_array[portid]->eth_tx_q_id = 0;
		RTE_LOG(WARNING, PKTJ1, "WARNING: No separate TX queue for KNI thread\n");
	}

	RTE_LOG(INFO, PKTJ1, "Creating queues: nb_rxq=%d nb_txq=%u...\n",
		nb_rx_queue, nb_tx_queue);

	if (kni_port_params_array[portid]->masq) {
		/* Configuring interfaces with checksum offload enabled */
		port_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM | RTE_ETH_RX_OFFLOAD_UDP_CKSUM;
		port_conf.txmode.offloads |= (RTE_ETH_TX_OFFLOAD_IPV4_CKSUM | RTE_ETH_TX_OFFLOAD_UDP_CKSUM |
			RTE_ETH_TX_OFFLOAD_TCP_CKSUM);
	}
	ret =
	    rte_eth_dev_configure(portid, nb_rx_queue, nb_tx_queue, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			 "Cannot configure device: err=%d, port=%u\n", ret,
			 portid);

	/*
	 * prepare dst and src MACs for each port.
	 */
	rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
	print_ethaddr(" Address:", &ports_eth_addr[portid]);

	txconf = &dev_info.default_txconf;

	socketid = 0;

	/* Creating TX queue for KNI thread */
	if (nb_tx_queue > nb_rx_queue) {
		ret = rte_eth_tx_queue_setup(portid, kni_port_params_array[portid]->eth_tx_q_id,
				nb_txd, socketid, txconf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup for KNI: err=%d, "
				 "port=%u\n",
				 ret, portid);
	}
	nb_tx_queue = 0;
	/* init one TX queue per couple (lcore,port) */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0) {
			continue;
		}

		socketid = 0;

		qconf = &lcore_conf[lcore_id];
		queueid = -1;

		/* init RX queues */
		for (queue = 0; queue < qconf->n_rx_queue; ++queue) {
			if (portid != qconf->rx_queue_list[queue].port_id) {
				// we skip that queue
				continue;
			}
			queueid = qconf->rx_queue_list[queue].queue_id;

			RTE_LOG(DEBUG, PKTJ1,
				"port=%u rx_queueid=%d nb_rxd=%d core=%u\n",
				portid, queueid, nb_rxd, lcore_id);
			ret = rte_eth_rx_queue_setup(portid, queueid, nb_rxd,
						     socketid, NULL,
						     pktmbuf_pool[socketid]);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					 "rte_eth_rx_queue_setup: err=%d,"
					 "port=%u\n",
					 ret, portid);
		}
		if (queueid == -1) {
			// no rx_queue set, don't need to setup tx_queue for
			// that clore
			continue;
		}

		RTE_LOG(
		    INFO, PKTJ1,
		    "\nInitializing rx/tx queues on lcore %u for port %u ...\n",
		    lcore_id, portid);

		rte_eth_dev_info_get(portid, &dev_info);
		txconf = &dev_info.default_txconf;

		RTE_LOG(DEBUG, PKTJ1,
			"port=%u tx_queueid=%d nb_txd=%d core=%u\n", portid,
			nb_tx_queue, nb_txd, lcore_id);
		ret = rte_eth_tx_queue_setup(portid, nb_tx_queue, nb_txd,
					     socketid, txconf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup: err=%d, "
				 "port=%u\n",
				 ret, portid);

		qconf->tx_queue_id[portid] = nb_tx_queue++;
	}
}

static void
signal_handler(int signum,
	       __rte_unused siginfo_t* si,
	       __rte_unused void* unused)
{
	int sock;

	/* When we receive a RTMIN or SIGINT signal, stop kni processing */
	if (signum == SIGRTMIN || signum == SIGINT || signum == SIGQUIT ||
	    signum == SIGTERM) {
		RTE_LOG(INFO, PKTJ1,
			"SIG %d is received, and the KNI processing is "
			"going to stop\n",
			signum);
		kni_stop_loop();
		rte_atomic32_inc(&main_loop_stop);

		for (sock = 0; sock < NB_SOCKETS; sock++) {
			if (control_handle4[sock].addr) {
				pktj_cmdline_stop(sock);
				control_stop(control_handle4[sock].addr);
				control_stop(control_handle6[sock].addr);
			}
		}
	} else if (signum == SIGCHLD) {
		int pid, status;
		if ((pid = wait(&status)) > 0) {
			RTE_LOG(INFO, PKTJ1,
				"SIGCHLD received, reaped child "
				"pid: %d status %d\n",
				pid, WEXITSTATUS(status));
		}
	}
}

static int
rdtsc_thread(__rte_unused void* args)
{
	int32_t f_stop;
	uint32_t i;
	uint64_t cur_tsc;

	while (1) {
		f_stop = rte_atomic32_read(&main_loop_stop);
		if (unlikely(f_stop))
			break;
		cur_tsc = rte_rdtsc();

		for (i = 0; i < RTE_MAX_LCORE; i++) {
			glob_tsc[i] = cur_tsc;
		}
		usleep(1000);
	}

	return 0;
}

static void
spawn_management_threads(uint32_t ctrlsock,
			 pthread_t* control_tid,
			 pthread_t* rdtsc_tid)
{
	unsigned lcore_id;
	int ret;
	char thread_name[16];
	cpu_set_t cset;

	lcore_id = control_handle4[ctrlsock].lcore_id;

	RTE_LOG(INFO, PKTJ1,
		"launching control thread for socketid "
		"%d on lcore %u\n",
		ctrlsock, lcore_id);
	pthread_create(&control_tid[0], NULL, (void*)control_main,
		       control_handle4[ctrlsock].addr);
	snprintf(thread_name, sizeof(thread_name), "control4-%d", ctrlsock);
	pthread_setname_np(control_tid[0], thread_name);
	cset = rte_lcore_cpuset(lcore_id);
	ret = pthread_setaffinity_np(control_tid[0], sizeof(cpu_set_t),
					&cset);
	if (ret != 0) {
		perror("control4 pthread_setaffinity_np: ");
		rte_exit(EXIT_FAILURE,
			 "control4 pthread_setaffinity_np "
			 "returned error: err=%d,",
			 ret);
	}
	pthread_create(&control_tid[1], NULL, (void*)control_main,
		       control_handle6[ctrlsock].addr);
	snprintf(thread_name, sizeof(thread_name), "control6-%d", ctrlsock);
	pthread_setname_np(control_tid[1], thread_name);
	cset = rte_lcore_cpuset(lcore_id);
	ret = pthread_setaffinity_np(control_tid[1], sizeof(cpu_set_t),
				     &cset);
	if (ret != 0) {
		perror("control6 pthread_setaffinity_np: ");
		rte_exit(EXIT_FAILURE,
			 "control6 pthread_setaffinity_np "
			 "returned error: err=%d,",
			 ret);
	}
	pthread_create(rdtsc_tid, NULL, (void*)rdtsc_thread, NULL);
	snprintf(thread_name, sizeof(thread_name), "rdtsc-%d", ctrlsock);
	pthread_setname_np(*rdtsc_tid, thread_name);
	cset = rte_lcore_cpuset(lcore_id);
	ret = pthread_setaffinity_np(*rdtsc_tid, sizeof(cpu_set_t),
					&cset);

	if (ret != 0) {
		perror("rdtsc pthread_setaffinity_np: ");
		rte_exit(EXIT_FAILURE,
			 "rdtsc pthread_setaffinity_np "
			 "returned error: err=%d,",
			 ret);
	}

	ret = pktj_cmdline_init(unixsock_path, ctrlsock);
	if (ret != 0) {
		rte_exit(EXIT_FAILURE, "pktj_cmdline_init failed");
	}
	cset = rte_lcore_cpuset(lcore_id);
	ret = pktj_cmdline_launch(ctrlsock, &cset);
	if (ret != 0) {
		rte_exit(EXIT_FAILURE, "pktj_cmdline_launch failed");
	}
}

int
main(int argc, char** argv)
{
	struct lcore_conf* qconf;
	int ret;
	unsigned lcore_id;
	uint8_t portid;
	pthread_t control_tid[2] = {0};  // ipv4 and ipv6 thread
	pthread_t rdtsc_tid;
	char thread_name[16];
	struct sigaction sa;
	uint32_t ctrlsock;
	uint16_t maxsock;
	int ipv4_sock_found = 0;
	uint32_t total_kni_t = 0;

	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = signal_handler;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}
	if (sigaction(SIGTERM, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}
	if (sigaction(SIGQUIT, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}
	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}

	if (prctl(PR_SET_CHILD_SUBREAPER, 1) < 0) {
		rte_exit(EXIT_FAILURE, "failed to prctl");
	}

	/* Sanitize lcore_conf */
	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		qconf = &lcore_conf[lcore_id];
		qconf->ipv4_lookup_struct = NULL;
		qconf->ipv6_lookup_struct = NULL;
		qconf->neighbor4_struct = NULL;
		qconf->neighbor6_struct = NULL;
	}

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

	snprintf(thread_name, 16, "lcore-master");
	pthread_setname_np(pthread_self(), thread_name);

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

	ret = init_lcore_rx_queues();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

	if (check_port_config(t_nb_ports) < 0)
		rte_exit(EXIT_FAILURE, "check_port_config failed\n");

	/* Add ACL rules and route entries, build trie */
	if (acl_init(0) < 0)
		rte_exit(EXIT_FAILURE, "acl_init ipv4 failed\n");
	if (acl_init(1) < 0)
		rte_exit(EXIT_FAILURE, "acl_init ipv6 failed\n");

	// look for any lcore not bound by dpdk (kni and eal) on each socket,
	// use it when found
	maxsock = 1;
	for (ctrlsock = 0; ctrlsock < maxsock; ctrlsock++) {
		control_handle4[ctrlsock].addr = NULL;
		control_handle6[ctrlsock].addr = NULL;
		qconf = NULL;

		// TODO: look for all available vcpus (not only eal
		// enabled lcores)
		RTE_LCORE_FOREACH(lcore_id)
		{
			if (rte_lcore_to_socket_id(lcore_id) == ctrlsock) {
				qconf = &lcore_conf[lcore_id];
				if (qconf->n_rx_queue == 0) {
					if (!ipv4_sock_found) {
						control_handle4[ctrlsock].addr =
						    control_init(
							ctrlsock,
							NETLINK4_EVENTS);
						control_handle4[ctrlsock]
						    .lcore_id = lcore_id;
						ipv4_sock_found = 1;
						control_handle6[ctrlsock].addr =
						    control_init(
							ctrlsock,
							NETLINK6_EVENTS);
						control_handle6[ctrlsock]
						    .lcore_id = lcore_id;
						break;
					}
				}
			}
		}

		if (qconf) {  // check if any lcore is enabled on this
			// socket
			if (control_handle4[ctrlsock].addr == NULL ||
			    control_handle6[ctrlsock].addr == NULL) {
				// if no lcore is available on this socket
				rte_exit(EXIT_FAILURE,
					 "no free lcore found on "
					 "socket %d for control 4 or 6, "
					 "exiting ...\n",
					 ctrlsock);
			}
		}
	}

	/* init memory */
	ret = init_mem();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_mem failed\n");

	if (ratelimit_file) {
		rate_limit_config_from_file(ratelimit_file);
	}

	/* initialize all ports */
	for (portid = 0; portid < t_nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		init_port(portid);

		/* KNI initialization*/
		init_port_tap(kni_port_params_array[portid]->port_id,
				kni_port_params_array[portid]->tx_queue_id);
	}

	/* start ports */
	for (portid = 0; portid < t_nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_dev_start: err=%d, port=%d\n", ret,
				 portid);
		/* start KNI */
		ret = rte_eth_dev_start(kni_port_params_array[portid]->port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "KNI rte_eth_dev_start: err=%d, port=%d\n", ret,
				 kni_port_params_array[portid]->port_id);

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (promiscuous_on) {
			rte_eth_promiscuous_enable(portid);
			rte_eth_promiscuous_enable(kni_port_params_array[portid]->port_id);
		}
		if (multicast_on) {
			rte_eth_allmulticast_enable(portid);
			rte_eth_allmulticast_enable(kni_port_params_array[portid]->port_id);
		}

		/* if NAT enabled on this port */
		if (kni_port_params_array[portid]->masq) {
			/* Init NAT free ports list */
			STAILQ_INIT(&nat_masq_entries);

			/* Populate all list */
			for (int k = 0; k < kni_port_params_array[portid]->count; k++) {
				struct nat_masq_entry *entry;

				entry = rte_zmalloc(NULL, sizeof(struct nat_masq_entry), 0);
				entry->key = rte_cpu_to_be_16(kni_port_params_array[portid]->base_port + k);
				STAILQ_INSERT_TAIL(&nat_masq_entries, entry, next);
			}

			char name[RTE_HASH_NAMESIZE];
			char reply_name[RTE_HASH_NAMESIZE];
			static struct rte_hash_parameters ut_params = {
				.entries = MAX_HASH_ENTRIES,
				.hash_func = rte_jhash,
				.hash_func_init_val = 0,
			};
			snprintf(name, sizeof(name), "port%u_nat", portid);
			snprintf(reply_name, sizeof(reply_name), "port%u_reply_nat", portid);
			/* creating hash table without locks */
			ut_params.extra_flag = 0;
			ut_params.name = name;
			ut_params.socket_id = rte_socket_id();
			ut_params.key_len = sizeof(uint16_t);
			kni_port_params_array[portid]->hash = rte_hash_create(&ut_params);
			if (kni_port_params_array[portid]->hash == NULL) {
				printf("Error creating hash table\n");
				return -1;
			}
			ut_params.name = reply_name;
			ut_params.key_len = sizeof(struct hash_value);
			kni_port_params_array[portid]->reply_hash = rte_hash_create(&ut_params);
			if (kni_port_params_array[portid]->reply_hash == NULL) {
				printf("Error creating reply hash table\n");
				return -1;
			}
		}
	}

	check_all_ports_link_status((uint8_t)t_nb_ports, enabled_port_mask);

	spawn_management_threads(0, control_tid, &rdtsc_tid);

	struct kni_args args[t_nb_ports];
	/* launch per-lcore init on every lcore */
	RTE_LCORE_FOREACH(lcore_id)
	{
		qconf = &lcore_conf[lcore_id];
		if (qconf->n_rx_queue != 0)
			rte_eal_remote_launch(main_loop, NULL, lcore_id);


		for (portid = 0; portid < t_nb_ports; portid++) {
			if ((enabled_port_mask & (1 << portid)) == 0) {
				continue;
			}
			if (kni_port_params_array[portid]->lcore_tx ==
			    lcore_id) {
				pthread_t kni_tid;

				RTE_LOG(INFO, PKTJ1,
					"launching kni thread on lcore %u\n",
					lcore_id);
				args[portid].lcore_id = lcore_id;
				args[portid].portid = portid;
				args[portid].eth_tx_q_id = kni_port_params_array[portid]->eth_tx_q_id;
				printf("args.portid = %d\n", args[portid].portid);
				pthread_create(&kni_tid, NULL,
					       (void*)kni_main_loop,
					       (void*)&args[portid]);

				snprintf(thread_name, 16, "kni-%u-%u", portid,
					 lcore_id);
				pthread_setname_np(kni_tid, thread_name);
				total_kni_t++;
			}
		}
	}
	RTE_LOG(INFO, PKTJ1, "Total kernel thread launched %d\n", total_kni_t);
	if (total_kni_t < nb_ports)
		RTE_LOG(WARNING, PKTJ1, "launched kni threads = %d, total ports = %d\n", total_kni_t, nb_ports);

	if ((ret = control_callback_setup(callback_setup, t_nb_ports))) {
		perror("control_callback_setup failure with: ");
		rte_exit(EXIT_FAILURE,
			 "control callback setup returned error: err=%d,", ret);
	}

	if (control_tid[0]) {
		pthread_join(control_tid[0], NULL);
	}
	if (control_tid[1]) {
		pthread_join(control_tid[1], NULL);
	}

	RTE_LCORE_FOREACH_WORKER(lcore_id)
	{
		RTE_LOG(INFO, PKTJ1, "waiting %u\n", lcore_id);
		if (rte_eal_wait_lcore(lcore_id) < 0)
			return -1;
	}
	RTE_LOG(INFO, PKTJ1, "rte_eal_wait_lcore finished\n");

	// childs will be handled here
	if (signal(SIGCHLD, SIG_DFL) == SIG_ERR) {
		rte_exit(EXIT_FAILURE, "failed to set sigaction");
	}
	ret = system("pkill -SIGTERM -P $PPID");
	RTE_LOG(INFO, PKTJ1, "killing remaining child processes: %d\n", ret);

	{
		int pid, status;
		while ((pid = wait(&status)) > 0) {
			RTE_LOG(DEBUG, PKTJ1,
				"Reaped child pid: %d status %d\n", pid,
				WEXITSTATUS(status));
		}
	}

	/* stop ports */
	for (portid = 0; portid < t_nb_ports; portid++) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		RTE_LOG(INFO, PKTJ1, "Stopping port id %d\n", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_stop(kni_port_params_array[portid]->port_id);
	}

	for (ctrlsock = 0; ctrlsock < NB_SOCKETS; ctrlsock++) {
		if (control_handle4[ctrlsock].addr) {
			pktj_cmdline_terminate(ctrlsock, unixsock_path);
			control_terminate(control_handle4[ctrlsock].addr);
			control_terminate(control_handle6[ctrlsock].addr);
		}
	}

	/* DPDK cleanup */
	rte_eal_cleanup();

	return 0;
}
