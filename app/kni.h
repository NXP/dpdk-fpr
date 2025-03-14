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
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024 NXP
 */

#ifndef __PKTJ_KNI_H
#define __PKTJ_KNI_H

#define KNI_MAX_KTHREAD 32

struct kni_args {
	unsigned lcore_id;
	uint8_t portid;
	uint8_t eth_tx_q_id;
};

int kni_main_loop(__rte_unused void* arg);
void kni_burst_free_mbufs(struct rte_mbuf** pkts, unsigned num, uint32_t lcore_id);
void kni_stop_loop(void);
/*
 * Structure of port parameters
 */
struct kni_port_params {
	uint16_t port_id; /* Port ID */
	uint8_t tx_queue_id;
	uint8_t eth_tx_q_id;
	unsigned lcore_tx;   /* lcore ID for TX */
	uint32_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
	uint32_t nb_kni;     /* Number of KNI devices to be created */
//	unsigned lcore_k[KNI_MAX_KTHREAD];    /* lcore ID list for kthreads */
	/* NAT related params */
	struct in_addr addr;
	uint8_t mask;
	uint8_t masq;
	uint16_t base_port;
	uint16_t count;
	struct rte_hash *hash;
	struct rte_hash *reply_hash;

} __rte_cache_aligned;

extern struct kni_port_params* kni_port_params_array[RTE_MAX_ETHPORTS];
extern uint8_t kni_port_rdy[RTE_MAX_ETHPORTS];

#endif
