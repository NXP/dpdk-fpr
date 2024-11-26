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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <getopt.h>

#include <rte_version.h>
#include <rte_string_fns.h>
#include <rte_mempool.h>
#include <rte_ethdev.h>
#include <rte_cfgfile.h>
#include <rte_malloc.h>
#include <rte_lpm6.h>
#include <cmdline_parse.h>
#include <cmdline_parse_ipaddr.h>

#include <libneighbour.h>

#include "common.h"
#include "routing.h"
#include "config.h"
#include "acl.h"
#include "kni.h"

#define FPR_NAT_BASE_PORT 50000
#define FPR_NAT_COUNT 1000
static struct lcore_params lcore_params_array[MAX_LCORE_PARAMS];

struct lcore_params* lcore_params;
uint16_t nb_lcore_params;

/* mask of enabled ports */
uint32_t enabled_port_mask = 0;
uint32_t t_nb_ports = 0;
uint32_t nb_ports = 0;
uint32_t enabled_kni_port_mask = 0;
int promiscuous_on = 0; /**< Ports set in promiscuous mode off by default. */
int multicast_on = 0; /**< Ports set in multicast mode off by default. */
uint32_t kni_rate_limit = UINT32_MAX;
const char* callback_setup = NULL;
const char* unixsock_path = "/tmp/fpr.sock";
const char* ratelimit_file = NULL;

struct rte_eth_conf port_conf = {0};

/* display usage */
void
print_usage(const char* prgname)
{
	RTE_LOG(
	    ERR, PKTJ1,
	    "%s [EAL options]\n"
	    "  [--configfile PATH: use a configfile for params]\n",
	    prgname);
}

static int
parse_max_pkt_len(const char* pktlen)
{
	char* end = NULL;
	unsigned long len;

	/* parse decimal string */
	len = strtoul(pktlen, &end, 10);
	if ((pktlen[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (len == 0)
		return -1;

	return len;
}

static void
print_kni_config(void)
{
	uint32_t i;
	struct kni_port_params** p = kni_port_params_array;

	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (!p[i])
			continue;
		RTE_LOG(DEBUG, PKTJ1, "Port ID: %d\n", p[i]->port_id);
		RTE_LOG(DEBUG, PKTJ1, "Tx lcore ID: %u\n", p[i]->lcore_tx);
	}
}

static int
nat_masq_parse_config_from_file(uint8_t port_id, char *q_arg)
{
	char *end;
	enum fieldnames {
		FLD_ENABLE = 0,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, nb_token;
	char *str_fld[_NUM_FLD];
	unsigned long int_fld[_NUM_FLD];

	nb_token = rte_strsplit(q_arg, strlen(q_arg), str_fld, _NUM_FLD, ',');

	if (nb_token <= FLD_ENABLE) {
		RTE_LOG(ERR, PKTJ1, "Invalid config parameters\n");
		return -1;
	}
	for (i = 0; i < nb_token; i++) {
		errno = 0;
		int_fld[i] = strtoul(str_fld[i], &end, 0);
		if (errno != 0 || end == str_fld[i]) {
			RTE_LOG(ERR, PKTJ1, "Invalid config parameters\n");
			return -1;
		}
	}

	kni_port_params_array[port_id]->masq = (uint8_t)int_fld[0];

	return 0;
}

static int
nat_port_parse_config_from_file(uint8_t port_id, char *q_arg)
{
	char *end;
	enum fieldnames { FLD_PORT = 0, FLD_COUNT, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;

	if (rte_strsplit(q_arg, strlen(q_arg), str_fld,
			 _NUM_FLD, ',') != _NUM_FLD) {
		return -1;
	}

	for (i = 0; i < _NUM_FLD; i++) {
		errno = 0;
		int_fld[i] = strtoul(str_fld[i], &end, 0);
		if (errno != 0 || end == str_fld[i])
			return -1;
	}

	kni_port_params_array[port_id]->base_port = (uint16_t)int_fld[0];
	kni_port_params_array[port_id]->count = (uint16_t)int_fld[1];

	return 0;
}


static int
kni_parse_config_from_file(uint8_t port_id, char* q_arg)
{
	char* end;
	enum fieldnames {
		FLD_LCORE = 0,
		_NUM_FLD = KNI_MAX_KTHREAD + 3,
	};
	int i, nb_token;
	char* str_fld[_NUM_FLD];
	unsigned long int_fld[_NUM_FLD];

	nb_token = rte_strsplit(q_arg, strlen(q_arg), str_fld, _NUM_FLD, ',');

	if (nb_token <= FLD_LCORE) {
		RTE_LOG(ERR, PKTJ1, "Invalid config parameters\n");
		goto fail;
	}
	for (i = 0; i < nb_token; i++) {
		errno = 0;
		int_fld[i] = strtoul(str_fld[i], &end, 0);
		if (errno != 0 || end == str_fld[i]) {
			RTE_LOG(ERR, PKTJ1, "Invalid config parameters\n");
			goto fail;
		}
	}

	if (port_id >= RTE_MAX_ETHPORTS) {
		RTE_LOG(ERR, PKTJ1,
			"Port ID %d could not exceed the maximum %d\n", port_id,
			RTE_MAX_ETHPORTS);
		goto fail;
	}
	if (kni_port_params_array[port_id]) {
		RTE_LOG(ERR, PKTJ1, "Port %d has already been configured\n",
			port_id);
		goto fail;
	}
	kni_port_params_array[port_id] = (struct kni_port_params*)rte_zmalloc(
	    "KNI_port_params", sizeof(struct kni_port_params),
	    RTE_CACHE_LINE_SIZE);

	kni_port_params_array[port_id]->tx_queue_id =
	    get_port_n_rx_queues(port_id) - 1;

	kni_port_params_array[port_id]->lcore_tx = (uint8_t)int_fld[FLD_LCORE];
	if (kni_port_params_array[port_id]->lcore_tx >= RTE_MAX_LCORE) {
		RTE_LOG(ERR, PKTJ1,
			"lcore_tx %u ID could not "
			"exceed the maximum %u\n",
			kni_port_params_array[port_id]->lcore_tx,
			(unsigned)RTE_MAX_LCORE);
		goto kni_fail;
	}
	kni_port_params_array[port_id]->nb_lcore_k = 1;
	return 0;

kni_fail:
	if (kni_port_params_array[port_id]) {
		rte_free(kni_port_params_array[port_id]);
		kni_port_params_array[port_id] = NULL;
	}
fail:

	return -1;
}

static int
parse_config_from_file(uint8_t port_id, char* q_arg)
{
	char* end;
	enum fieldnames { FLD_QUEUE = 0, FLD_LCORE, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	char* str_fld[_NUM_FLD];
	char* str_tuples[MAX_LCORE_PARAMS];
	int i, j, nb_tuples;

	nb_tuples = rte_strsplit(q_arg, strlen(q_arg), str_tuples,
				 MAX_LCORE_PARAMS, ' ');

	for (j = 0; j < nb_tuples; j++) {
		if (rte_strsplit(str_tuples[j], strlen(str_tuples[j]), str_fld,
				 _NUM_FLD, ',') != _NUM_FLD) {
			return -1;
		}

		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] ||
			    int_fld[i] > 255) {
				return -1;
			}
		}

		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			RTE_LOG(ERR, PKTJ1,
				"exceeded max number of lcore params: %hu\n",
				nb_lcore_params);
			return -1;
		}
		lcore_params_array[nb_lcore_params].port_id = port_id;
		lcore_params_array[nb_lcore_params].queue_id =
		    (uint8_t)int_fld[FLD_QUEUE];
		lcore_params_array[nb_lcore_params].lcore_id =
		    (uint8_t)int_fld[FLD_LCORE];
		++nb_lcore_params;
	}

	lcore_params = lcore_params_array;
	return 0;
}

static int
rate_limit_ipv4(union rlimit_addr* addr, uint32_t num, int socket_id)
{
	uint8_t range_id;
	static uint8_t next_range_id[NB_SOCKETS] = {0};

	range_id = rlimit4_lookup_table[socket_id][addr->network];
	// check if this cidr range is the lookup table
	if (range_id == INVALID_RLIMIT_RANGE) {
		range_id = next_range_id[socket_id]++;

		if (range_id >= MAX_RLIMIT_RANGE) {  // if not found
			return -1;
		}
	}

	// set slot for this cidr range in the lookup table
	// and set the max packet rate for this dest addr
	rlimit4_lookup_table[socket_id][addr->network] = range_id;
	rlimit4_max[socket_id][range_id][addr->host] = num;

	return 0;
}

static int
rate_limit_ipv6(cmdline_ipaddr_t* ip, uint32_t num, int socket_id)
{
	static uint16_t next_hop_count[NB_SOCKETS] = {0};
	lpm6_neigh next_hop = 0;

	// store the rule so it can applied once
	// it is added if it is not already

	// check if this address is already stored
	for (next_hop = 0; next_hop < NEI_NUM_ENTRIES - 1; next_hop++) {
		// if addresses match
		if (!memcmp(&rlimit6_lookup_table[socket_id][next_hop].addr,
			    &ip->addr.ipv6, sizeof(struct in6_addr))) {
			break;
		}
	}

	// otherwise try to allocate new slot for storage
	if (next_hop == NEI_NUM_ENTRIES - 1) {
		// no more slot available
		if (next_hop_count[socket_id] == NEI_NUM_ENTRIES - 2) {
			return -1;
		}

		next_hop = next_hop_count[socket_id]++;
	}

	rte_memcpy(&rlimit6_lookup_table[socket_id][next_hop].addr,
		   &ip->addr.ipv6, sizeof(struct in6_addr));
	rlimit6_lookup_table[socket_id][next_hop].num = num;

	if (rte_lpm6_lookup(ipv6_pktj_lookup_struct[socket_id],
			    ip->addr.ipv6.s6_addr, &next_hop) == 0) {
		// set the max packet rate for this neighbor
		rlimit6_max[socket_id][next_hop] = num;
	}

	return 0;
}

int
rate_limit_address(cmdline_ipaddr_t* ip, uint32_t num, int socket_id)
{
	int i, res;
	uint32_t netmask, netaddr, maxhost, j;

	res = 0;
	if (ip->family == AF_INET) {
		if (ip->prefixlen > 0) {
			// rate limit range
			netmask = ~(UINT32_MAX >> ip->prefixlen);
			netaddr =
			    rte_be_to_cpu_32(ip->addr.ipv4.s_addr) & netmask;
			maxhost = netaddr + (1 << (32 - ip->prefixlen));
			if (socket_id == SOCKET_ID_ANY) {
				for (i = 0; i < NB_SOCKETS; i++) {
					for (j = netaddr; j < maxhost; j++) {
						rate_limit_ipv4(
						    (union rlimit_addr*)&j, num,
						    i);
					}
				}
			} else {
				for (j = netaddr; j < maxhost; j++) {
					rate_limit_ipv4((union rlimit_addr*)&j,
							num, socket_id);
				}
			}
		} else {
			netaddr = rte_be_to_cpu_32(ip->addr.ipv4.s_addr);
			if (socket_id == SOCKET_ID_ANY) {
				for (i = 0; i < NB_SOCKETS; i++) {
					res += rate_limit_ipv4(
					    (union rlimit_addr*)&netaddr, num,
					    i);
				}
			} else {
				res = rate_limit_ipv4(
				    (union rlimit_addr*)&netaddr, num,
				    socket_id);
			}
		}
	} else if (ip->family == AF_INET6) {
		if (socket_id == SOCKET_ID_ANY) {  // rate limit for all sockets
			for (i = 0; i < NB_SOCKETS; i++) {
				res += rate_limit_ipv6(ip, num, i);
			}
		} else {
			res = rate_limit_ipv6(ip, num, socket_id);
		}
	}

	return res;
}

void
rate_limit_config_from_file(const char* file_name)
{
	char buff[LINE_MAX];
	enum fieldnames { FLD_ADDRESS = 0, FLD_RATE, _NUM_FLD };
	char* str_fld[_NUM_FLD];
	cmdline_parse_token_ipaddr_t tk, tk_net;
	cmdline_ipaddr_t ip_addr;
	uint32_t num;

	FILE* fh = fopen(file_name, "rb");

	if (fh == NULL) {
		RTE_LOG(ERR, PKTJ1,
			"Could not open rate limit config file: %s\n",
			file_name);
		return;
	}

	tk.ipaddr_data.flags = CMDLINE_IPADDR_V4 | CMDLINE_IPADDR_V6;
	tk_net.ipaddr_data.flags =
	    CMDLINE_IPADDR_V4 | CMDLINE_IPADDR_V6 | CMDLINE_IPADDR_NETWORK;

	while ((fgets(buff, LINE_MAX, fh) != NULL)) {
		if (rte_strsplit(buff, strlen(buff), str_fld, _NUM_FLD, ' ') !=
		    _NUM_FLD) {
			continue;
		}

		sscanf(str_fld[FLD_RATE], "%u", &num);
		if (cmdline_parse_ipaddr((cmdline_parse_token_hdr_t*)&tk_net,
					 str_fld[FLD_ADDRESS], &ip_addr,
					 sizeof(ip_addr)) > 0 ||
		    cmdline_parse_ipaddr((cmdline_parse_token_hdr_t*)&tk,
					 str_fld[FLD_ADDRESS], &ip_addr,
					 sizeof(ip_addr)) > 0) {
			if (rate_limit_address(&ip_addr, num, SOCKET_ID_ANY) ==
			    0) {
				RTE_LOG(INFO, PKTJ1, "rate limited %s to %d\n",
					str_fld[FLD_ADDRESS], num);
			}
		} else {  // invalid address
			RTE_LOG(ERR, PKTJ1, "could not rate limit %s to %d\n",
				str_fld[FLD_ADDRESS], num);
		}
	}

	fclose(fh);
}

#define MAX_EAL 100
#define MAX_EAL_LINE_SIZE 200
static int
install_cfgfile(const char* file_name, char* prgname)
{
	struct rte_cfgfile* file;
	uint32_t i, nb_available_kni = 0;
	const char* entry;
	char section_name[16], *ptr;
	int ret = 0, port_id;
	char *eal_args[MAX_EAL];
	int eal_argc = 0, k, count;
	struct rte_cfgfile_entry entries[PKTJ_MAX_EAL];
	const char eal_delimiters[] = " =";


	if (file_name[0] == '\0')
		return -1;

	file = rte_cfgfile_load(file_name, 0);
	if (file == NULL) {
		rte_exit(EXIT_FAILURE, "Config file %s not found\n", file_name);
	}

	nb_ports = (uint32_t)rte_cfgfile_num_sections(file, "port",
						     sizeof("port") - 1);

	if (nb_ports >= RTE_MAX_ETHPORTS) {
		rte_exit(EXIT_FAILURE,
			 "Ports %d could not exceed the maximum %d\n", nb_ports,
			 RTE_MAX_ETHPORTS);
	}

	RTE_LOG(DEBUG, PKTJ1, "Got configuration for nb_ports = %d\n", nb_ports);
	/* READ EAL params */
	count = rte_cfgfile_section_num_entries(file, "eal");
	if (count <= 0)
		rte_exit(EXIT_FAILURE, "No eal parameters available\n");

	if (count > PKTJ_MAX_EAL)
		rte_exit(EXIT_FAILURE, "Too many eal parameters\n");

	ret = rte_cfgfile_section_entries(file, "eal", entries, count);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Failed to get eal entries\n");

	eal_args[eal_argc++] = prgname;
	for (k = 0; k < count; k++) {
		char line[MAX_EAL_LINE_SIZE];
		char *token;

		strncpy(line, entries[k].value, MAX_EAL_LINE_SIZE - 1);
		line[MAX_EAL_LINE_SIZE - 1] = '\0';
		token = strtok(line, eal_delimiters);
		while (token != NULL && eal_argc < MAX_EAL) {
			eal_args[eal_argc] = strdup(token);
			eal_argc++;
			token = strtok(NULL, eal_delimiters);
		}
	}

	/* INIT DPDK */
	ret = rte_eal_init(eal_argc, eal_args);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

	nb_lcore_params = 0;
	memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));

	for (i = 0; i < nb_ports; i++) {
		snprintf(section_name, sizeof(section_name), "port %u", i);
		if (!rte_cfgfile_has_section(file, section_name))
			rte_exit(EXIT_FAILURE,
				 "Config file parse error: port IDs are not "
				 "sequential (port %u missing)\n",
				 i);

		enabled_port_mask |= (1 << i);

		entry = rte_cfgfile_get_entry(file, section_name, "eal queues");
		if (!entry)
			rte_exit(
			    EXIT_FAILURE,
			    "Config file parse error: EAL queues for port %u "
			    "not defined\n",
			    i);

		ptr = strdup(entry);
		if (!ptr)
			rte_exit(EXIT_FAILURE,
				 "Config file parse error: Could "
				 "not allocate memory for "
				 "strdup\n");
		ret = parse_config_from_file(i, ptr);
		free(ptr);

		if (ret)
			rte_exit(EXIT_FAILURE, "invalid config, refer help\n");

		entry = rte_cfgfile_get_entry(file, section_name, "kni");
		if (!entry)
			rte_exit(EXIT_FAILURE,
				 "Config file parse error: KNI "
				 "core queues for port %u "
				 "not defined\n",
				 i);

		ptr = strdup(entry);
		if (!ptr)
			rte_exit(EXIT_FAILURE,
				 "Config file parse error: Could "
				 "not allocate memory for "
				 "strdup\n");
		ret = kni_parse_config_from_file(i, ptr);
		free(ptr);

		if (ret)
			rte_exit(EXIT_FAILURE, "Invalid config, refer help\n");

		entry = rte_cfgfile_get_entry(file, section_name, "nat_ip_masquerade");
		if (entry) {
			ptr = strdup(entry);
			if (!ptr)
				rte_exit(EXIT_FAILURE,
					 "Config file parse error: Could "
					 "not allocate memory for "
					 "strdup\n");
			ret = nat_masq_parse_config_from_file(i, ptr);
			if (ret)
				rte_exit(EXIT_FAILURE, "invalid config, refer help\n");
			free(ptr);

			entry = rte_cfgfile_get_entry(file, section_name, "nat_port");
			if (entry) {
				ptr = strdup(entry);
				if (!ptr)
					rte_exit(EXIT_FAILURE,
						 "Config file parse error: Could "
						 "not allocate memory for "
						 "strdup\n");
				ret = nat_port_parse_config_from_file(i, ptr);
				if (ret)
					rte_exit(EXIT_FAILURE, "invalid config, refer help\n");
				free(ptr);
			} else {
				/* setting default values */
				kni_port_params_array[i]->base_port = (uint16_t)FPR_NAT_BASE_PORT;
				kni_port_params_array[i]->count = (uint16_t)FPR_NAT_COUNT;
			}
		}
	}

	/* Check for total interfaces, there must be equal number of vitio/tap interfaces */
	RTE_ETH_FOREACH_DEV(port_id) {
		struct rte_eth_dev_info dev_info;

		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE, "failed to get device info\n");

		t_nb_ports++;
		if (!strcmp(dev_info.driver_name, "net_tap") ||
			!strcmp(dev_info.driver_name, "net_virtio_user")) {
			enabled_kni_port_mask |= (1 << port_id);
			nb_available_kni++;
			continue;
		}

	}

	RTE_LOG(DEBUG, PKTJ1, "Available ports = %d Enabled physical ports = %d, "
			"kni ports = %d, physical port mask = 0x%x, KNI port mask = 0x%x\n",
			t_nb_ports, nb_ports, nb_available_kni, enabled_port_mask, enabled_kni_port_mask);
	/* Check given configuration is for actual interfaces? */
	if (enabled_kni_port_mask & enabled_port_mask) {
		rte_exit(EXIT_FAILURE, "Actual port mask 0x%x is matching with KNI ports 0x%x\n",
					enabled_port_mask, enabled_kni_port_mask);
	}

	if (nb_available_kni < nb_ports) 
		rte_exit(EXIT_FAILURE, "KNIs are less than physical interfaces\n");

	uint32_t temp_kni_mask = enabled_kni_port_mask;
	/* Do the port mapping for KNI interfaces */
	RTE_ETH_FOREACH_DEV(port_id) {
		uint32_t reset_mask;

		if (!(enabled_port_mask & (1 << port_id)))
			continue;
		/* find the free KNI for mapping */
		for (int k = 0; k < RTE_MAX_ETHPORTS; k++) {
			if (temp_kni_mask & (1 << k)) {
				kni_port_params_array[port_id]->port_id = k;
				reset_mask = 1 << k;
				temp_kni_mask = temp_kni_mask & ~reset_mask;
				break;
			}
		}
		if (k == RTE_MAX_ETHPORTS)
			rte_exit(EXIT_FAILURE, "failed to map KNI to actual port\n");
	}

	/* Dumping the mapping */
	RTE_ETH_FOREACH_DEV(port_id) {
		if (!(enabled_port_mask & (1 << port_id)))
			continue;

		RTE_LOG(INFO, PKTJ1, "Physical port = %d and mapped kni = %d\n", port_id,
				kni_port_params_array[port_id]->port_id);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_UNIXSOCK);
	if (entry) {
		unixsock_path = strdup(entry);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_CALLBACK_SETUP);
	if (entry) {
		callback_setup = strdup(entry);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_KNI_RATE_LIMIT);
	if (entry) {
		if ((ret = strtoul(entry, NULL, 0)) > 0) {
			kni_rate_limit = ret;
		}
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_RULE_IPV4);
	if (entry) {
		acl_parm_config.rule_ipv4_name = strdup(entry);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_RULE_IPV6);
	if (entry) {
		acl_parm_config.rule_ipv6_name = strdup(entry);
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_RATE_LIMIT);
	if (entry) {
		ratelimit_file = strdup(entry);
	}

	/*      optional    */
	entry =
	    rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG, CMD_LINE_OPT_PROMISC);
	if (entry) {
		if (strtoul(entry, NULL, 0)) {
			RTE_LOG(INFO, PKTJ1, "Promiscuous mode selected\n");
			promiscuous_on = 1;
		}
	}
	/*      optional    */
	entry =
	    rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG, CMD_LINE_OPT_MULTICAST);
	if (entry) {
		if (strtoul(entry, NULL, 0)) {
			RTE_LOG(INFO, PKTJ1, "Multicast mode selected\n");
			multicast_on = 1;
		}
	}

	entry =
	    rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG, CMD_LINE_OPT_ACLNEON);
	if (entry) {
		if (strtoul(entry, NULL, 0)) {
			acl_parm_config.aclneon = 1;
		}
	}

	entry = rte_cfgfile_get_entry(file, FILE_MAIN_CONFIG,
				      CMD_LINE_OPT_MAXPKT_LEN);
	if (entry) {
		ret = parse_max_pkt_len(entry);
		if ((ret < 64) || (ret > MAX_JUMBO_PKT_LEN))
			rte_exit(EXIT_FAILURE,
				"invalid packet length, refer help\n");
		/* Storing the MTU after removing the overhead.
		 * Driver will configure the MAX frame length accordingly.
		 * TODO: update it as per the driver supported packet overhead.
		 */
		port_conf.rxmode.mtu = ret - (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN);
		RTE_LOG(INFO, PKTJ1,
			"set frame max packet length to %u\n",
			(unsigned int)port_conf.rxmode.mtu + (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN));
	}

	print_kni_config();

/*FIXME: issue in free after calling rte_eal_init() */
#if 0
	for (k = 0; k < eal_argc; k++)
		free(eal_args[k]);
#endif
	rte_cfgfile_close(file);

	return ret;
}

/* Parse the argument given in the command line of the application */
int
parse_args(int argc, char** argv)
{
	int opt, ret = 0;
	char* prgname = argv[0];

	for (opt = 1; opt < argc; opt++) {
		if (strcmp(argv[opt], "--configfile") == 0 &&
		    argv[opt + 1] != NULL) {
			return install_cfgfile(argv[opt + 1], prgname);
		}
	}

	print_usage(prgname);

	return ret;
}
