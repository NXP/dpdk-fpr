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
 * Copyright 2024 NXP
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <sched.h>

#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>

#include <rte_version.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_bus_pci.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_log.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_string_fns.h>
#include <rte_cycles.h>
#include <rte_malloc.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>

#include <libneighbour.h>

#include "common.h"
#include "routing.h"
#include "kni.h"
#include "config.h"

#define KNI_BURST 8

struct kni_port_params* kni_port_params_array[RTE_MAX_ETHPORTS];
uint8_t kni_port_rdy[RTE_MAX_ETHPORTS] = {0};

static rte_atomic32_t kni_stop = RTE_ATOMIC32_INIT(0);

void
kni_burst_free_mbufs(struct rte_mbuf** pkts, unsigned num, uint32_t lcore_id)
{
	unsigned i;

	if (pkts == NULL)
		return;

	for (i = 0; i < num; i++) {
		rte_pktmbuf_free(pkts[i]);
		stats[lcore_id].nb_kni_dropped++;
		pkts[i] = NULL;
	}
}

void
kni_stop_loop(void)
{
	rte_atomic32_inc(&kni_stop);
}

int
kni_main_loop(void* arg)
{
	int32_t f_stop;
	unsigned port_id;
	int nb_rx, ret;
	uint32_t lcore_id;
	struct rte_mbuf* pkts_burst[MAX_PKT_BURST];
	cpu_set_t cpuset;
	struct kni_args *args = (struct kni_args *)arg;

	RTE_LOG(INFO, PKTJ1, "port id = %d and lcore id =%d\n", args->portid, args->lcore_id);

	/* TODO:Support statistics for multiple ports, loop iterations */
	stats[args->lcore_id].port_id = args->portid;
	CPU_ZERO(&cpuset);
        CPU_SET(lcore_id, &cpuset);
	port_id = args->portid;
	lcore_id = args->lcore_id; 

	RTE_LOG(INFO, PKTJ1, "entering kni main loop portid %u\n", port_id);
        ret = pthread_setaffinity_np(
                                    pthread_self(), sizeof(cpu_set_t), &cpuset);
        if (ret != 0) {
                 perror("kni pthread_setaffinity_np: ");
                 rte_exit(EXIT_FAILURE,
                          "kni pthread_setaffinity_np "
                          "returned error: err=%d,",
                                                ret);
                                }
	while (1) {
		f_stop = rte_atomic32_read(&kni_stop);
		if (f_stop)
			break;

		stats[lcore_id].nb_iteration_looped++;
		nb_rx = rte_eth_rx_burst(kni_port_params_array[port_id]->port_id, 0, pkts_burst,
                                         KNI_BURST);
		stats[lcore_id].nb_kni_rx += nb_rx;
		if (nb_rx) {
			ret = rte_eth_tx_burst(port_id, args->eth_tx_q_id, &pkts_burst[0], nb_rx);
                        if (ret != nb_rx) {
				RTE_LOG(DEBUG, PKTJ1, "TX failed port = %d, pkts = %d\n", port_id, nb_rx - ret);
				kni_burst_free_mbufs(&pkts_burst[ret], nb_rx - ret, lcore_id);
			}
			stats[lcore_id].nb_tx += nb_rx;
		}
		usleep(1000);
	}

	return 0;
}
