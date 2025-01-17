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
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <termios.h>
#include <unistd.h>
#include <poll.h>
#include <signal.h>

#include <rte_version.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_lcore.h>
#include <rte_lpm.h>
#include <rte_lpm6.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>

#include <cmdline_rdline.h>
#include <cmdline_parse.h>
#include <cmdline_socket.h>
#include <cmdline_parse_ipaddr.h>
#include <cmdline_parse_num.h>
#include <cmdline_parse_string.h>
#include <cmdline.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libneighbour.h>

#include "common.h"
#include "cmdline.h"
#include "routing.h"
#include "acl.h"
#include "stats.h"
#include "config.h"

#define CMDLINE_POLL_TIMEOUT 500

#ifdef __clang__
# pragma clang diagnostic ignored "-Wformat-nonliteral"
#elif __GNUC__
# pragma GCC diagnostic ignored "-Wformat-nonliteral"
#endif
static pthread_t cmdline_tid[NB_SOCKETS];

struct client_data_t cmdline_clients[NB_SOCKETS][CMDLINE_MAX_CLIENTS];
static volatile sig_atomic_t cmdline_thread_loop[NB_SOCKETS];
static int cmdline_thread_unixsock[NB_SOCKETS];
RTE_DEFINE_PER_LCORE(uint32_t, g_socket_id);

static void
port_rss_reta_info(portid_t port_id,
		   struct rte_eth_rss_reta_entry64* reta_conf,
		   uint16_t nb_entries)
{
	uint16_t i, idx, shift;
	int ret;

	ret = rte_eth_dev_rss_reta_query(port_id, reta_conf, nb_entries);
	if (ret != 0) {
		RTE_LOG(ERR, CMDLINE1,
			"Failed to get RSS RETA info, return code = %d\n", ret);
		return;
	}

	for (i = 0; i < nb_entries; i++) {
		idx = i / RTE_ETH_RETA_GROUP_SIZE;
		shift = i % RTE_ETH_RETA_GROUP_SIZE;
		if (!(reta_conf[idx].mask & (1ULL << shift)))
			continue;
		RTE_LOG(ERR, CMDLINE1,
			"RSS RETA configuration: hash index=%u, queue=%u\n", i,
			reta_conf[idx].reta[shift]);
	}
}

/* *** SET LOGLEVEL *** */
struct cmd_loglevel_result {
	cmdline_fixed_string_t loglevel;
	uint8_t level;
};

static void
cmd_loglevel_parsed(void* parsed_result,
		    __rte_unused struct cmdline* cl,
		    __rte_unused void* data)
{
	struct cmd_loglevel_result* res = parsed_result;
#if RTE_VERSION >= RTE_VERSION_NUM(17,5,0,0)
	rte_log_set_global_level(res->level);
#else
	rte_set_log_level(res->level);
#endif
}

cmdline_parse_token_string_t cmd_loglevel_loglevel =
    TOKEN_STRING_INITIALIZER(struct cmd_loglevel_result, loglevel, "loglevel");
cmdline_parse_token_num_t cmd_loglevel_level =
    TOKEN_NUM_INITIALIZER(struct cmd_loglevel_result, level, RTE_UINT8);

cmdline_parse_inst_t cmd_loglevel = {
    .f = cmd_loglevel_parsed,
    .data = NULL,
    .help_str = "loglevel level",
    .tokens =
	{
	    (void *)&cmd_loglevel_loglevel, (void *)&cmd_loglevel_level, NULL,
	},
};

/* *** SET LOGTYPE *** */
struct cmd_logtype_result {
	cmdline_fixed_string_t logtype;
	uint8_t type;
	uint8_t enable;
};

static void
cmd_logtype_parsed(void* parsed_result,
		   __rte_unused struct cmdline* cl,
		   __rte_unused void* data)
{
	struct cmd_logtype_result* res = parsed_result;

	if (res->type == 255)
		rte_log_set_level_pattern("*", res->enable ? rte_log_get_global_level() : 0);
	else
		rte_log_set_level(res->type, res->enable ? rte_log_get_global_level() : 0);
}

cmdline_parse_token_string_t cmd_logtype_logtype =
    TOKEN_STRING_INITIALIZER(struct cmd_logtype_result, logtype, "logtype");
cmdline_parse_token_num_t cmd_logtype_type =
    TOKEN_NUM_INITIALIZER(struct cmd_logtype_result, type, RTE_UINT8);
cmdline_parse_token_num_t cmd_logtype_enable =
    TOKEN_NUM_INITIALIZER(struct cmd_logtype_result, enable, RTE_UINT8);

cmdline_parse_inst_t cmd_logtype = {
    .f = cmd_logtype_parsed,
    .data = NULL,
    .help_str = "logtype type enable",
    .tokens =
	{
	    (void *)&cmd_logtype_logtype, (void *)&cmd_logtype_type,
	    (void *)&cmd_logtype_enable, NULL,
	},
};

/* *** Show LOGTYPES and LEVELS *** */
struct pktj_cmd_loglevel_values {
	cmdline_fixed_string_t logs;
	cmdline_fixed_string_t path;
};

static void
pktj_cmd_loglevel_display(void* parsed_result,
		   __rte_unused struct cmdline* cl,
		   __rte_unused void* data)
{
	struct pktj_cmd_loglevel_values* res = parsed_result;
	FILE *fd;

	fd = fopen(res->path, "w");
        if (fd == NULL) {
                cmdline_printf(cl, "failed to open file %s\n", res->path);
                return;
        }

	rte_log_dump(fd);
	fclose(fd);
}

cmdline_parse_token_string_t pktj_cmd_loglevel_string =
    TOKEN_STRING_INITIALIZER(struct pktj_cmd_loglevel_values, logs, "dumploglevel");
cmdline_parse_token_string_t pktj_cmd_loglevel_path =
    TOKEN_STRING_INITIALIZER(struct pktj_cmd_loglevel_values, path, NULL);

cmdline_parse_inst_t pktj_cmd_loglevel_show = {
    .f = pktj_cmd_loglevel_display,
    .data = NULL,
    .help_str = "dumpoglevel <file>",
    .tokens =
	{
	    (void *)&pktj_cmd_loglevel_string,
	    (void *)&pktj_cmd_loglevel_path,
	    NULL,
	},
};


/* *** SHOW PORT INFO *** */
struct cmd_showport_result {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t what;
	uint8_t portnum;
	cmdline_fixed_string_t option;
};

static void
cmd_showport_parsed(void* parsed_result, struct cmdline* cl, void* data)
{
	struct cmd_showport_result* res = parsed_result;
	if (!strcmp(res->show, "clear")) {
		if (!strcmp(res->what, "stats"))
			nic_stats_clear(cl, res->portnum);
		else if (!strcmp(res->what, "xstats"))
			nic_xstats_clear(cl, res->portnum);
	} else if (!strcmp(res->what, "info"))
		port_infos_display(cl, res->portnum);
	else if (!strcmp(res->what, "stats"))
		nic_stats_display(cl, res->portnum, (intptr_t)data);
	else if (!strcmp(res->what, "xstats"))
		nic_xstats_display(cl, res->portnum, (intptr_t)data);
}

cmdline_parse_token_string_t cmd_showport_show =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_result, show, "show#clear");
cmdline_parse_token_string_t cmd_showport_port =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_result, port, "port");
cmdline_parse_token_string_t cmd_showport_what =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_result,
			     what,
			     "info#stats#xstats");
cmdline_parse_token_num_t cmd_showport_portnum =
    TOKEN_NUM_INITIALIZER(struct cmd_showport_result, portnum, RTE_UINT8);
cmdline_parse_token_string_t cmd_showport_option =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_result, option, "-j#json");

cmdline_parse_inst_t cmd_showport = {
    .f = cmd_showport_parsed,
    .data = NULL,
    .help_str = "show|clear port info|stats|xstats X (X = port number)",
    .tokens =
	{
	    (void *)&cmd_showport_show, (void *)&cmd_showport_port,
	    (void *)&cmd_showport_what, (void *)&cmd_showport_portnum, NULL,
	},
};

cmdline_parse_inst_t cmd_showport_json = {
    .f = cmd_showport_parsed,
    .data = (void*)1,
    .help_str = "show|clear port info|stats|xstats X (X = port number)",
    .tokens =
	{
	    (void *)&cmd_showport_show, (void *)&cmd_showport_port,
	    (void *)&cmd_showport_what, (void *)&cmd_showport_portnum,
	    (void *)&cmd_showport_option, NULL,
	},
};

/*
 * Displays the RSS hash functions of a port, and, optionaly, the RSS hash
 * key of the port.
 */
/* *** Show RSS hash configuration *** */
struct cmd_showport_rss_hash {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	uint8_t port_id;
	cmdline_fixed_string_t rss_hash;
	cmdline_fixed_string_t key; /* optional argument */
};

static void
cmd_showport_rss_hash_parsed(void* parsed_result,
			     struct cmdline* cl,
			     void* show_rss_key)
{
	struct cmd_showport_rss_hash* res = parsed_result;

	port_rss_hash_conf_show(cl, res->port_id, show_rss_key != NULL);
}

cmdline_parse_token_string_t cmd_showport_rss_hash_show =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, show, "show");
cmdline_parse_token_string_t cmd_showport_rss_hash_port =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, port, "port");
cmdline_parse_token_num_t cmd_showport_rss_hash_port_id =
    TOKEN_NUM_INITIALIZER(struct cmd_showport_rss_hash, port_id, RTE_UINT8);
cmdline_parse_token_string_t cmd_showport_rss_hash_rss_hash =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash,
			     rss_hash,
			     "rss-hash");
cmdline_parse_token_string_t cmd_showport_rss_hash_rss_key =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_rss_hash, key, "key");

cmdline_parse_inst_t cmd_showport_rss_hash = {
    .f = cmd_showport_rss_hash_parsed,
    .data = NULL,
    .help_str = "show port X rss-hash (X = port number)\n",
    .tokens =
	{
	    (void *)&cmd_showport_rss_hash_show,
	    (void *)&cmd_showport_rss_hash_port,
	    (void *)&cmd_showport_rss_hash_port_id,
	    (void *)&cmd_showport_rss_hash_rss_hash, NULL,
	},
};

cmdline_parse_inst_t cmd_showport_rss_hash_key = {
    .f = cmd_showport_rss_hash_parsed,
    .data = (void*)1,
    .help_str = "show port X rss-hash key (X = port number)\n",
    .tokens =
	{
	    (void *)&cmd_showport_rss_hash_show,
	    (void *)&cmd_showport_rss_hash_port,
	    (void *)&cmd_showport_rss_hash_port_id,
	    (void *)&cmd_showport_rss_hash_rss_hash,
	    (void *)&cmd_showport_rss_hash_rss_key, NULL,
	},
};

/* *** configure rss *** */
struct cmd_config_rss {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	cmdline_fixed_string_t all;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t value;
};

static void
cmd_config_rss_parsed(void* parsed_result,
		      __attribute__((unused)) struct cmdline* cl,
		      __attribute__((unused)) void* data)
{
	struct cmd_config_rss* res = parsed_result;
	struct rte_eth_rss_conf rss_conf;
	uint8_t i;

	if (!strcmp(res->value, "all"))
		rss_conf.rss_hf = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP |
				  RTE_ETH_RSS_SCTP | RTE_ETH_RSS_L2_PAYLOAD;
	else if (!strcmp(res->value, "ip"))
		rss_conf.rss_hf = RTE_ETH_RSS_IP;
	else if (!strcmp(res->value, "udp"))
		rss_conf.rss_hf = RTE_ETH_RSS_UDP;
	else if (!strcmp(res->value, "tcp"))
		rss_conf.rss_hf = RTE_ETH_RSS_TCP;
	else if (!strcmp(res->value, "sctp"))
		rss_conf.rss_hf = RTE_ETH_RSS_SCTP;
	else if (!strcmp(res->value, "ether"))
		rss_conf.rss_hf = RTE_ETH_RSS_L2_PAYLOAD;
	else if (!strcmp(res->value, "none"))
		rss_conf.rss_hf = 0;
	else {
		RTE_LOG(ERR, CMDLINE1, "Unknown parameter\n");
		return;
	}
	rss_conf.rss_key = NULL;
#ifdef RTE_ETH_FOREACH_DEV
	RTE_ETH_FOREACH_DEV(i)
		rte_eth_dev_rss_hash_update(i, &rss_conf);
#else
	for (i = 0; i < rte_eth_dev_count(); i++)
		rte_eth_dev_rss_hash_update(i, &rss_conf);
#endif
}

cmdline_parse_token_string_t cmd_config_rss_port =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss, port, "port");
cmdline_parse_token_string_t cmd_config_rss_keyword =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss, keyword, "config");
cmdline_parse_token_string_t cmd_config_rss_all =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss, all, "all");
cmdline_parse_token_string_t cmd_config_rss_name =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss, name, "rss");
cmdline_parse_token_string_t cmd_config_rss_value =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss,
			     value,
			     "all#ip#tcp#udp#sctp#ether#none");

cmdline_parse_inst_t cmd_config_rss = {
    .f = cmd_config_rss_parsed,
    .data = NULL,
    .help_str = "port config all rss all|ip|tcp|udp|sctp|ether|none",
    .tokens =
	{
	    (void *)&cmd_config_rss_port, (void *)&cmd_config_rss_keyword,
	    (void *)&cmd_config_rss_all, (void *)&cmd_config_rss_name,
	    (void *)&cmd_config_rss_value, NULL,
	},
};

/* *** configure rss hash key *** */
struct cmd_config_rss_hash_key {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t config;
	uint8_t port_id;
	cmdline_fixed_string_t rss_hash_key;
	cmdline_fixed_string_t key;
};

static uint8_t
hexa_digit_to_value(char hexa_digit)
{
	if ((hexa_digit >= '0') && (hexa_digit <= '9'))
		return (uint8_t)(hexa_digit - '0');
	if ((hexa_digit >= 'a') && (hexa_digit <= 'f'))
		return (uint8_t)((hexa_digit - 'a') + 10);
	if ((hexa_digit >= 'A') && (hexa_digit <= 'F'))
		return (uint8_t)((hexa_digit - 'A') + 10);
	/* Invalid hexa digit */
	return 0xFF;
}

static uint8_t
parse_and_check_key_hexa_digit(struct cmdline* cl, char* key, int idx)
{
	uint8_t hexa_v;

	hexa_v = hexa_digit_to_value(key[idx]);
	if (hexa_v == 0xFF)
		cmdline_printf(
		    cl,
		    "invalid key: character %c at position %d is not a "
		    "valid hexa digit\n",
		    key[idx], idx);
	return hexa_v;
}

static void
cmd_config_rss_hash_key_parsed(void* parsed_result,
			       struct cmdline* cl,
			       __rte_unused void* data)
{
	struct cmd_config_rss_hash_key* res = parsed_result;
	uint8_t hash_key[RSS_HASH_KEY_LENGTH];
	uint8_t xdgt0;
	uint8_t xdgt1;
	int i;

	/* Check the length of the RSS hash key */
	if (strlen(res->key) != (RSS_HASH_KEY_LENGTH * 2)) {
		cmdline_printf(
		    cl,
		    "key length: %d invalid - key must be a string of %d"
		    "hexa-decimal numbers\n",
		    (int)strlen(res->key), RSS_HASH_KEY_LENGTH * 2);
		return;
	}
	/* Translate RSS hash key into binary representation */
	for (i = 0; i < RSS_HASH_KEY_LENGTH; i++) {
		xdgt0 = parse_and_check_key_hexa_digit(cl, res->key, (i * 2));
		if (xdgt0 == 0xFF)
			return;
		xdgt1 =
		    parse_and_check_key_hexa_digit(cl, res->key, (i * 2) + 1);
		if (xdgt1 == 0xFF)
			return;
		hash_key[i] = (uint8_t)((xdgt0 * 16) + xdgt1);
	}
	port_rss_hash_key_update(cl, res->port_id, hash_key);
}

cmdline_parse_token_string_t cmd_config_rss_hash_key_port =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, port, "port");
cmdline_parse_token_string_t cmd_config_rss_hash_key_config =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, config, "config");
cmdline_parse_token_num_t cmd_config_rss_hash_key_port_id =
    TOKEN_NUM_INITIALIZER(struct cmd_config_rss_hash_key, port_id, RTE_UINT8);
cmdline_parse_token_string_t cmd_config_rss_hash_key_rss_hash_key =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key,
			     rss_hash_key,
			     "rss-hash-key");
cmdline_parse_token_string_t cmd_config_rss_hash_key_value =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_hash_key, key, NULL);

cmdline_parse_inst_t cmd_config_rss_hash_key = {
    .f = cmd_config_rss_hash_key_parsed,
    .data = NULL,
    .help_str = "port config X rss-hash-key 104 hexa digits",
    .tokens =
	{
	    (void *)&cmd_config_rss_hash_key_port,
	    (void *)&cmd_config_rss_hash_key_config,
	    (void *)&cmd_config_rss_hash_key_port_id,
	    (void *)&cmd_config_rss_hash_key_rss_hash_key,
	    (void *)&cmd_config_rss_hash_key_value, NULL,
	},
};

/* *** Configure RSS RETA *** */
struct cmd_config_rss_reta {
	cmdline_fixed_string_t port;
	cmdline_fixed_string_t keyword;
	uint8_t port_id;
	cmdline_fixed_string_t name;
	cmdline_fixed_string_t list_name;
	cmdline_fixed_string_t list_of_items;
};

static int
parse_reta_config(const char* str,
		  struct rte_eth_rss_reta_entry64* reta_conf,
		  uint16_t nb_entries)
{
	int i;
	unsigned size;
	uint16_t hash_index, idx, shift;
	uint8_t nb_queue;
	char s[256];
	const char *p, *p0 = str;
	char* end;
	enum fieldnames { FLD_HASH_INDEX = 0, FLD_QUEUE, _NUM_FLD };
	unsigned long int_fld[_NUM_FLD];
	char* str_fld[_NUM_FLD];

	while ((p = strchr(p0, '(')) != NULL) {
		++p;
		if ((p0 = strchr(p, ')')) == NULL)
			return -1;

		size = p0 - p;
		if (size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') !=
		    _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++) {
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] ||
			    int_fld[i] > 65535)
				return -1;
		}

		hash_index = (uint16_t)int_fld[FLD_HASH_INDEX];
		nb_queue = (uint8_t)int_fld[FLD_QUEUE];

		if (hash_index >= nb_entries) {
			RTE_LOG(ERR, CMDLINE1, "Invalid RETA hash index=%d\n",
				hash_index);
			return -1;
		}

		idx = hash_index / RTE_ETH_RETA_GROUP_SIZE;
		shift = hash_index % RTE_ETH_RETA_GROUP_SIZE;
		reta_conf[idx].mask |= (1ULL << shift);
		reta_conf[idx].reta[shift] = nb_queue;
	}

	return 0;
}

static void
cmd_set_rss_reta_parsed(void* parsed_result,
			struct cmdline* cl,
			__rte_unused void* data)
{
	int ret;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_rss_reta_entry64 reta_conf[8];
	struct cmd_config_rss_reta* res = parsed_result;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(res->port_id, &dev_info);
	if (dev_info.reta_size == 0) {
		cmdline_printf(cl,
			       "Redirection table size is 0 which is "
			       "invalid for RSS\n");
		return;
	} else
		cmdline_printf(cl, "The reta size of port %d is %u\n",
			       res->port_id, dev_info.reta_size);
	if (dev_info.reta_size > RTE_ETH_RSS_RETA_SIZE_512) {
		cmdline_printf(
		    cl,
		    "Currently do not support more than %u entries of "
		    "redirection table\n",
		    RTE_ETH_RSS_RETA_SIZE_512);
		return;
	}

	memset(reta_conf, 0, sizeof(reta_conf));
	if (!strcmp(res->list_name, "reta")) {
		if (parse_reta_config(res->list_of_items, reta_conf,
				      dev_info.reta_size)) {
			cmdline_printf(cl,
				       "Invalid RSS Redirection Table "
				       "config entered\n");
			return;
		}
		ret = rte_eth_dev_rss_reta_update(res->port_id, reta_conf,
						  dev_info.reta_size);
		if (ret != 0)
			cmdline_printf(cl,
				       "Bad redirection table parameter, "
				       "return code = %d \n",
				       ret);
	}
}

cmdline_parse_token_string_t cmd_config_rss_reta_port =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, port, "port");
cmdline_parse_token_string_t cmd_config_rss_reta_keyword =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, keyword, "config");
cmdline_parse_token_num_t cmd_config_rss_reta_port_id =
    TOKEN_NUM_INITIALIZER(struct cmd_config_rss_reta, port_id, RTE_UINT8);
cmdline_parse_token_string_t cmd_config_rss_reta_name =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, name, "rss");
cmdline_parse_token_string_t cmd_config_rss_reta_list_name =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, list_name, "reta");
cmdline_parse_token_string_t cmd_config_rss_reta_list_of_items =
    TOKEN_STRING_INITIALIZER(struct cmd_config_rss_reta, list_of_items, NULL);
cmdline_parse_inst_t cmd_config_rss_reta = {
    .f = cmd_set_rss_reta_parsed,
    .data = NULL,
    .help_str = "port config X rss reta (hash,queue)[,(hash,queue)]",
    .tokens =
	{
	    (void *)&cmd_config_rss_reta_port,
	    (void *)&cmd_config_rss_reta_keyword,
	    (void *)&cmd_config_rss_reta_port_id,
	    (void *)&cmd_config_rss_reta_name,
	    (void *)&cmd_config_rss_reta_list_name,
	    (void *)&cmd_config_rss_reta_list_of_items, NULL,
	},
};

/* *** SHOW PORT RETA INFO *** */
struct cmd_showport_reta {
	cmdline_fixed_string_t show;
	cmdline_fixed_string_t port;
	uint8_t port_id;
	cmdline_fixed_string_t rss;
	cmdline_fixed_string_t reta;
	uint16_t size;
	cmdline_fixed_string_t list_of_items;
};

static int
showport_parse_reta_config(struct rte_eth_rss_reta_entry64* conf,
			   uint16_t nb_entries,
			   char* str)
{
	uint32_t size;
	const char *p, *p0 = str;
	char s[256];
	char* end;
	char* str_fld[8];
	uint16_t i, num = nb_entries / RTE_ETH_RETA_GROUP_SIZE;
	int ret;

	p = strchr(p0, '(');
	if (p == NULL)
		return -1;
	p++;
	p0 = strchr(p, ')');
	if (p0 == NULL)
		return -1;
	size = p0 - p;
	if (size >= sizeof(s)) {
		RTE_LOG(ERR, CMDLINE1,
			"The string size exceeds the internal buffer size\n");
		return -1;
	}
	snprintf(s, sizeof(s), "%.*s", size, p);
	ret = rte_strsplit(s, sizeof(s), str_fld, num, ',');
	if (ret <= 0 || ret != num) {
		RTE_LOG(ERR, CMDLINE1,
			"The bits of masks do not match the number of "
			"reta entries: %u\n",
			num);
		return -1;
	}
	for (i = 0; i < ret; i++)
		conf[i].mask = (uint64_t)strtoul(str_fld[i], &end, 0);

	return 0;
}

static void
cmd_showport_reta_parsed(void* parsed_result,
			 __attribute__((unused)) struct cmdline* cl,
			 __attribute__((unused)) void* data)
{
	struct cmd_showport_reta* res = parsed_result;
	struct rte_eth_rss_reta_entry64 reta_conf[8];
	struct rte_eth_dev_info dev_info;

	memset(&dev_info, 0, sizeof(dev_info));
	rte_eth_dev_info_get(res->port_id, &dev_info);
	if (dev_info.reta_size == 0 || res->size != dev_info.reta_size ||
	    res->size > RTE_ETH_RSS_RETA_SIZE_512) {
		RTE_LOG(ERR, CMDLINE1, "Invalid redirection table size: %u\n",
			res->size);
		return;
	}

	memset(reta_conf, 0, sizeof(reta_conf));
	if (showport_parse_reta_config(reta_conf, res->size,
				       res->list_of_items) < 0) {
		RTE_LOG(ERR, CMDLINE1, "Invalid string: %s for reta masks\n",
			res->list_of_items);
		return;
	}
	port_rss_reta_info(res->port_id, reta_conf, res->size);
}

cmdline_parse_token_string_t cmd_showport_reta_show =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, show, "show");
cmdline_parse_token_string_t cmd_showport_reta_port =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, port, "port");
cmdline_parse_token_num_t cmd_showport_reta_port_id =
    TOKEN_NUM_INITIALIZER(struct cmd_showport_reta, port_id, RTE_UINT8);
cmdline_parse_token_string_t cmd_showport_reta_rss =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, rss, "rss");
cmdline_parse_token_string_t cmd_showport_reta_reta =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, reta, "reta");
cmdline_parse_token_num_t cmd_showport_reta_size =
    TOKEN_NUM_INITIALIZER(struct cmd_showport_reta, size, RTE_UINT16);
cmdline_parse_token_string_t cmd_showport_reta_list_of_items =
    TOKEN_STRING_INITIALIZER(struct cmd_showport_reta, list_of_items, NULL);

cmdline_parse_inst_t cmd_showport_reta = {
    .f = cmd_showport_reta_parsed,
    .data = NULL,
    .help_str = "show port X rss reta (size) (mask0,mask1,...)",
    .tokens =
	{
	    (void *)&cmd_showport_reta_show, (void *)&cmd_showport_reta_port,
	    (void *)&cmd_showport_reta_port_id, (void *)&cmd_showport_reta_rss,
	    (void *)&cmd_showport_reta_reta, (void *)&cmd_showport_reta_size,
	    (void *)&cmd_showport_reta_list_of_items, NULL,
	},
};

//----- CMD LPM_LKP

struct cmd_obj_lpm_lkp_result {
	cmdline_fixed_string_t action;
	cmdline_ipaddr_t ip;
};

static void
cmd_obj_lpm_lkp_parsed(void* parsed_result,
		       struct cmdline* cl,
		       __rte_unused void* data)
{
	struct cmd_obj_lpm_lkp_result *res = parsed_result;
	uint32_t next_hop;
	lpm6_neigh next_hop6;
	int i;
	char buf[INET6_ADDRSTRLEN];

	if (res->ip.family == AF_INET) {
		i = rte_lpm_lookup(
		    ipv4_pktj_lookup_struct[RTE_PER_LCORE(g_socket_id)],
		    rte_be_to_cpu_32(res->ip.addr.ipv4.s_addr), &next_hop);
		if (i < 0) {
			cmdline_printf(cl, "not found\n");
		} else {
			struct in_addr* addr =
			    &neighbor4_struct[RTE_PER_LCORE(g_socket_id)]
				 ->entries.t4[next_hop]
				 .addr;
			cmdline_printf(
			    cl, "present, next_hop %s\n",
			    inet_ntop(AF_INET, addr, buf, INET6_ADDRSTRLEN));
		}
	} else if (res->ip.family == AF_INET6) {
		i = rte_lpm6_lookup(
		    ipv6_pktj_lookup_struct[RTE_PER_LCORE(g_socket_id)],
		    res->ip.addr.ipv6.s6_addr, &next_hop6);
		if (i < 0) {
			cmdline_printf(cl, "not found\n");
		} else {
			struct in6_addr* addr =
			    &neighbor6_struct[RTE_PER_LCORE(g_socket_id)]
				 ->entries.t6[next_hop6]
				 .addr;
			cmdline_printf(
			    cl, "present, next_hop %s\n",
			    inet_ntop(AF_INET6, addr, buf, INET6_ADDRSTRLEN));
		}
	}
}

cmdline_parse_token_string_t cmd_obj_action_lpm_lkp =
    TOKEN_STRING_INITIALIZER(struct cmd_obj_lpm_lkp_result, action, "lpm_lkp");
cmdline_parse_token_ipaddr_t cmd_obj_lpm_ip =
    TOKEN_IPADDR_INITIALIZER(struct cmd_obj_lpm_lkp_result, ip);

cmdline_parse_inst_t cmd_obj_lpm_lkp = {
    .f = cmd_obj_lpm_lkp_parsed, /* function to call */
    .data = NULL,		 /* 2nd arg of func */
    .help_str = "Do a lookup in lpm table (ip)",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_obj_action_lpm_lkp, (void *)&cmd_obj_lpm_ip, NULL,
	},
};

//----- CMD RLIMIT
struct cmd_obj_rlimit_result {
	cmdline_fixed_string_t action;
	cmdline_ipaddr_t ip;
	uint32_t num;
};

static void
cmd_obj_rlimit_parsed(void* parsed_result,
		      struct cmdline* cl,
		      __rte_unused void* data)
{
	struct cmd_obj_rlimit_result* res = parsed_result;
	char buf[INET6_ADDRSTRLEN];
	int ret;

	if (res->num == 0) {  // remove rate limiting
		res->num = UINT32_MAX;
	}
	ret =
	    rate_limit_address(&res->ip, res->num, RTE_PER_LCORE(g_socket_id));
	if (ret < 0) {
		if (res->ip.family == AF_INET) {
			cmdline_printf(
			    cl, "could not find free array slot for %s \n",
			    inet_ntop(AF_INET, &res->ip.addr.ipv4, buf,
				      INET6_ADDRSTRLEN));
		} else {
			cmdline_printf(cl, "not found\n");
		}
		return;
	}

	cmdline_printf(
	    cl, "rate limited %s/%d to %d\n",
	    inet_ntop(res->ip.family, &res->ip.addr, buf, INET6_ADDRSTRLEN),
	    res->ip.prefixlen == 0 ? 32 : res->ip.prefixlen, res->num);
}

cmdline_parse_token_string_t cmd_obj_action_rlimit =
    TOKEN_STRING_INITIALIZER(struct cmd_obj_rlimit_result, action, "rlimit");
cmdline_parse_token_ipaddr_t cmd_obj_rlimit_ip =
    TOKEN_IPADDR_INITIALIZER(struct cmd_obj_rlimit_result, ip);
cmdline_parse_token_ipaddr_t cmd_obj_rlimit_ipnet =
    TOKEN_IPNET_INITIALIZER(struct cmd_obj_rlimit_result, ip);
cmdline_parse_token_num_t cmd_obj_rlimit_num =
    TOKEN_NUM_INITIALIZER(struct cmd_obj_rlimit_result, num, RTE_UINT32);

cmdline_parse_inst_t cmd_obj_rlimit = {
    .f = cmd_obj_rlimit_parsed, /* function to call */
    .data = NULL,		/* 2nd arg of func */
    .help_str = "Rate limit an address (rate in pps per queue)",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_obj_action_rlimit, (void *)&cmd_obj_rlimit_ip,
	    (void *)&cmd_obj_rlimit_num, NULL,
	},
};

cmdline_parse_inst_t cmd_obj_rlimit_net = {
    .f = cmd_obj_rlimit_parsed, /* function to call */
    .data = NULL,		/* 2nd arg of func */
    .help_str = "Rate limit a network (rate in pps per queue)",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_obj_action_rlimit, (void *)&cmd_obj_rlimit_ipnet,
	    (void *)&cmd_obj_rlimit_num, NULL,
	},
};

//----- CMD ACL_ADD

struct cmd_obj_acl_add_result {
	cmdline_fixed_string_t action;
	cmdline_fixed_string_t proto;
	cmdline_fixed_string_t path;
};

static void
cmd_obj_acl_add_parsed(void* parsed_result,
		       struct cmdline* cl,
		       __rte_unused void* data)
{
	struct cmd_obj_acl_add_result* res = parsed_result;
	int is_ipv4;

	is_ipv4 = !strcmp(res->proto, "ipv4");
	if (is_ipv4) {
		acl_parm_config.rule_ipv4_name = res->path;
	} else {
		acl_parm_config.rule_ipv6_name = res->path;
	}
	if (acl_init(is_ipv4)) {
		cmdline_printf(cl, "ERROR: failed to add acl\n");
	}
}

cmdline_parse_token_string_t cmd_obj_action_acl_add =
    TOKEN_STRING_INITIALIZER(struct cmd_obj_acl_add_result, action, "acl_add");
cmdline_parse_token_string_t cmd_obj_acl_proto =
    TOKEN_STRING_INITIALIZER(struct cmd_obj_acl_add_result, proto, "ipv4#ipv6");
cmdline_parse_token_string_t cmd_obj_acl_path =
    TOKEN_STRING_INITIALIZER(struct cmd_obj_acl_add_result, path, NULL);

cmdline_parse_inst_t cmd_obj_acl_add = {
    .f = cmd_obj_acl_add_parsed, /* function to call */
    .data = NULL,		 /* 2nd arg of func */
    .help_str = "Add an acl (aclfile path, ip version)",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_obj_action_acl_add, (void *)&cmd_obj_acl_proto,
	    (void *)&cmd_obj_acl_path, NULL,
	},
};

//----- CMD STATS

struct cmd_stats_result {
	cmdline_fixed_string_t stats;
	cmdline_fixed_string_t option;
	uint8_t delay;
};

static void
cmd_stats_parsed(void* parsed_result, struct cmdline* cl, void* data)
{
	struct cmd_stats_result* res = (struct cmd_stats_result*)parsed_result;
	pktj_stats_display(cl, (intptr_t)data, res->delay);
}

cmdline_parse_token_string_t cmd_stats_stats =
    TOKEN_STRING_INITIALIZER(struct cmd_stats_result, stats, "stats");
cmdline_parse_token_string_t cmd_stats_stats_json =
    TOKEN_STRING_INITIALIZER(struct cmd_stats_result, option, "-j#json");
cmdline_parse_token_string_t cmd_stats_stats_csv =
    TOKEN_STRING_INITIALIZER(struct cmd_stats_result, option, "-c#csv");
cmdline_parse_token_num_t cmd_stats_stats_delay =
    TOKEN_NUM_INITIALIZER(struct cmd_stats_result, delay, RTE_UINT8);

cmdline_parse_inst_t cmd_stats = {
    .f = cmd_stats_parsed, /* function to call */
    .data = NULL,	  /* 2nd arg of func */
    .help_str = "show stats",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void*)&cmd_stats_stats, NULL,
	},
};

cmdline_parse_inst_t cmd_stats_json = {
    .f = cmd_stats_parsed,	 /* function to call */
    .data = (void*)CMD_STATS_JSON, /* 2nd arg of func */
    .help_str = "show stats",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_stats_stats, (void *)&cmd_stats_stats_json, NULL,
	},
};

cmdline_parse_inst_t cmd_stats_csv = {
    .f = cmd_stats_parsed,	/* function to call */
    .data = (void*)CMD_STATS_CSV, /* 2nd arg of func */
    .help_str = "show stats",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_stats_stats, (void *)&cmd_stats_stats_csv,
	    (void *)&cmd_stats_stats_delay, NULL,
	},
};

//----- CMD LPM_STATS

struct cmd_lpm_stats_result {
	cmdline_fixed_string_t stats;
	cmdline_fixed_string_t proto;
	cmdline_fixed_string_t option;
};

static void
cmd_lpm_stats_parsed(void* parsed_result, struct cmdline* cl, void* data)
{
	struct cmd_lpm_stats_result* res = parsed_result;
	int is_ipv4;

	is_ipv4 = !strcmp(res->proto, "ipv4");
	pktj_lpm_stats_display(cl, is_ipv4, (intptr_t)data);
}

cmdline_parse_token_string_t cmd_lpm_stats_stats =
    TOKEN_STRING_INITIALIZER(struct cmd_lpm_stats_result, stats, "lpm_stats");
cmdline_parse_token_string_t cmd_lpm_stats_proto =
    TOKEN_STRING_INITIALIZER(struct cmd_lpm_stats_result, proto, "ipv4#ipv6");
cmdline_parse_token_string_t cmd_lpm_stats_stats_json =
    TOKEN_STRING_INITIALIZER(struct cmd_lpm_stats_result, option, "-j#json");

cmdline_parse_inst_t cmd_lpm_stats = {
    .f = cmd_lpm_stats_parsed,    /* function to call */
    .data = (void*)CMD_LPM_STATS, /* 2nd arg of func */
    .help_str = "show lpm_stats",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_lpm_stats_stats, (void *)&cmd_lpm_stats_proto, NULL,
	},
};

cmdline_parse_inst_t cmd_lpm_stats_json = {
    .f = cmd_lpm_stats_parsed,	 /* function to call */
    .data = (void*)CMD_LPM_STATS_JSON, /* 2nd arg of func */
    .help_str = "show lpm_stats",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_lpm_stats_stats, (void *)&cmd_lpm_stats_proto,
	    (void *)&cmd_lpm_stats_stats_json, NULL,
	},
};

//----- CMD NEIGH
struct cmd_neigh_result {
	cmdline_fixed_string_t neigh;
	cmdline_fixed_string_t proto;
};

static void
cmd_neigh_parsed(void* parsed_result,
		 struct cmdline* cl,
		 __rte_unused void* data)
{
	struct cmd_neigh_result* res = parsed_result;
	int is_ipv4;
	int i;
	struct nei_table* t;
	char buf_eth[RTE_ETHER_ADDR_FMT_SIZE];
	char buf_ip[INET6_ADDRSTRLEN];

	is_ipv4 = !strcmp(res->proto, "ipv4");
	if (is_ipv4) {
		struct nei_entry4* entry;
		t = neighbor4_struct[RTE_PER_LCORE(g_socket_id)];

		for (i = 0; i < NEI_NUM_ENTRIES; i++) {
			entry = &(t->entries.t4[i]);
			if (entry->neighbor.in_use &&
					entry->neighbor.action == NEI_ACTION_FWD) {
				rte_ether_format_addr(
				    buf_eth, sizeof(buf_eth),
				    &entry->neighbor.nexthop_hwaddr);
				cmdline_printf(
				    cl,
				    "hw addr(%s) addr(%s) action %d state "
				    "%d vlan %d port %d\n",
				    buf_eth,
				    inet_ntop(AF_INET, &entry->addr, buf_ip,
					      INET6_ADDRSTRLEN),
				    entry->neighbor.action,
				    entry->neighbor.state,
				    entry->neighbor.vlan_id,
				    entry->neighbor.port_id);
			}
		}
	} else {
		struct nei_entry6* entry;
		t = neighbor6_struct[RTE_PER_LCORE(g_socket_id)];

		for (i = 0; i < NEI_NUM_ENTRIES; i++) {
			entry = &(t->entries.t6[i]);
			if (entry->neighbor.in_use &&
					entry->neighbor.action == NEI_ACTION_FWD) {
				rte_ether_format_addr(
				    buf_eth, sizeof(buf_eth),
				    &entry->neighbor.nexthop_hwaddr);
				cmdline_printf(
				    cl,
				    "hw addr(%s) addr(%s) action %d state "
				    "%d vlan %d port %d\n",
				    buf_eth,
				    inet_ntop(AF_INET6, &entry->addr, buf_ip,
					      INET6_ADDRSTRLEN),
				    entry->neighbor.action,
				    entry->neighbor.state,
				    entry->neighbor.vlan_id,
				    entry->neighbor.port_id);
			}
		}
	}
}

cmdline_parse_token_string_t cmd_neigh_neigh =
    TOKEN_STRING_INITIALIZER(struct cmd_neigh_result, neigh, "neigh");
cmdline_parse_token_string_t cmd_neigh_proto =
    TOKEN_STRING_INITIALIZER(struct cmd_neigh_result, proto, "ipv4#ipv6");

cmdline_parse_inst_t cmd_neigh = {
    .f = cmd_neigh_parsed, /* function to call */
    .data = NULL,	  /* 2nd arg of func */
    .help_str = "neigh ipv4#ipv6",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void *)&cmd_neigh_neigh, (void *)&cmd_neigh_proto, NULL,
	},
};

//----- CMD DUMP lpm
struct cmd_dump_lpm_result {
	cmdline_fixed_string_t lpm;
	cmdline_fixed_string_t proto;
	cmdline_fixed_string_t path;
};

static void
cmd_dump_lpm_parsed(void* parsed_result,
		 struct cmdline* cl,
		 __rte_unused void* data)
{
	struct cmd_dump_lpm_result* res = parsed_result;
	int is_ipv4;
	FILE * flpm;

	flpm = fopen(res->path, "w");
	if (flpm == NULL) {
		cmdline_printf(cl, "failed to open file %s\n", res->path);
		return;
	}
	is_ipv4 = !strcmp(res->proto, "ipv4");
	if (is_ipv4) {
		struct rte_lpm *t = ipv4_pktj_lookup_struct[RTE_PER_LCORE(g_socket_id)];
		fwrite(t, sizeof(*t), 1, flpm);
		fwrite("1234567890", 1, 10, flpm);
		//fwrite(t->tbl8, sizeof(*t->tbl8), t->number_tbl8s, flpm);
	}/* else {
		struct rte_lpm6 *t = ipv6_pktj_lookup_struct[RTE_PER_LCORE(g_socket_id)];
		fwrite(t, sizeof(*t), 1, flpm);
		fwrite("1234567890", 1, 10, flpm);
		fwrite(t->tbl8, sizeof(*t->tbl8), t->number_tbl8s, flpm);
	}*/
	fclose(flpm);
}

cmdline_parse_token_string_t cmd_dump_lpm_lpm =
    TOKEN_STRING_INITIALIZER(struct cmd_dump_lpm_result, lpm, "dump_lpm");
cmdline_parse_token_string_t cmd_dump_lpm_proto =
    TOKEN_STRING_INITIALIZER(struct cmd_dump_lpm_result, proto, "ipv4#ipv6");
cmdline_parse_token_string_t cmd_dump_lpm_path =
    TOKEN_STRING_INITIALIZER(struct cmd_dump_lpm_result, path, NULL);

cmdline_parse_inst_t cmd_dump_lpm = {
    .f = cmd_dump_lpm_parsed, /* function to call */
    .data = NULL,	  /* 2nd arg of func */
    .help_str = "dump_lpm ipv4#ipv6",
    .tokens =
	{
		/* token list, NULL terminated */
		(void *)&cmd_dump_lpm_lpm,
		(void *)&cmd_dump_lpm_proto,
		(void *)&cmd_dump_lpm_path,
		NULL,
	},
};


//----- CMD DUMP NEIGH
struct cmd_dump_neigh_result {
	cmdline_fixed_string_t neigh;
	cmdline_fixed_string_t proto;
	cmdline_fixed_string_t path;
};

static void
cmd_dump_neigh_parsed(void* parsed_result,
		 struct cmdline* cl,
		 __rte_unused void* data)
{
	struct cmd_dump_neigh_result* res = parsed_result;
	int is_ipv4;
	struct nei_table* t;
	FILE * fneigh;

	fneigh = fopen(res->path, "w");
	if (fneigh == NULL) {
		cmdline_printf(cl, "failed to open file %s\n", res->path);
		return;
	}
	is_ipv4 = !strcmp(res->proto, "ipv4");
	if (is_ipv4) {
		int i;
		struct nei_entry4 *entry;
		char buf_eth[RTE_ETHER_ADDR_FMT_SIZE];
		char buf_ip[INET6_ADDRSTRLEN];

		t = neighbor4_struct[RTE_PER_LCORE(g_socket_id)];
		for (i = 0; i < NEI_NUM_ENTRIES; i++) {
                        entry = &(t->entries.t4[i]);
                                rte_ether_format_addr(
                                    buf_eth, sizeof(buf_eth),
                                    &entry->neighbor.nexthop_hwaddr);
                                fprintf(fneigh,
                                    "hw addr(%s) addr(%s) action %d state "
                                    "%d vlan %d port %d\n",
                                    buf_eth,
                                    inet_ntop(AF_INET, &entry->addr, buf_ip,
                                              INET6_ADDRSTRLEN),
                                    entry->neighbor.action,
                                    entry->neighbor.state,
                                    entry->neighbor.vlan_id,
                                    entry->neighbor.port_id);
                }
	} else {
		t = neighbor6_struct[RTE_PER_LCORE(g_socket_id)];
		/* IPV6 is not supported FIXME */
	}
	fclose(fneigh);
}

cmdline_parse_token_string_t cmd_dump_neigh_neigh =
    TOKEN_STRING_INITIALIZER(struct cmd_dump_neigh_result, neigh, "dump_neigh");
cmdline_parse_token_string_t cmd_dump_neigh_proto =
    TOKEN_STRING_INITIALIZER(struct cmd_dump_neigh_result, proto, "ipv4#ipv6");
cmdline_parse_token_string_t cmd_dump_neigh_path =
    TOKEN_STRING_INITIALIZER(struct cmd_dump_neigh_result, path, NULL);

cmdline_parse_inst_t cmd_dump_neigh = {
    .f = cmd_dump_neigh_parsed, /* function to call */
    .data = NULL,	  /* 2nd arg of func */
    .help_str = "dump_neigh ipv4#ipv6",
    .tokens =
	{
		/* token list, NULL terminated */
		(void *)&cmd_dump_neigh_neigh,
		(void *)&cmd_dump_neigh_proto,
		(void *)&cmd_dump_neigh_path,
		NULL,
	},
};

//----- CMD HELP

struct cmd_help_result {
	cmdline_fixed_string_t help;
};

static void
cmd_help_parsed(__attribute__((unused)) void* parsed_result,
		struct cmdline* cl,
		__attribute__((unused)) void* data)
{
	cmdline_printf(
	    cl,
	    "commands:\n"
	    "- stats [-j , -c sec]\n"
	    "- { show | clear } port { info | stats | xstats } port_id\n"
	    "- neigh { ipv4 | ipv6 }\n"
	    "- acl_add { ipv4 | ipv6 } file_path\n"
	    "- lpm_lkp IP[/DEPTH]\n"
	    "- lpm_stats { ipv4 | ipv6 }\n"
	    "- loglevel level\n"
	    "- logtype type_id { 0 | 1 }\n"
	    "- dumploglevel file_path\n"
	    "- rlimit IP rate\n"
	    "- dump_neigh { ipv4 | ipv6 } file_path\n"
	    "- help\n\n");
}

cmdline_parse_token_string_t cmd_help_help =
    TOKEN_STRING_INITIALIZER(struct cmd_help_result, help, "help");

cmdline_parse_inst_t cmd_help = {
    .f = cmd_help_parsed, /* function to call */
    .data = NULL,	 /* 2nd arg of func */
    .help_str = "show help",
    .tokens =
	{
	    /* token list, NULL terminated */
	    (void*)&cmd_help_help, NULL,
	},
};

//----- !CMD HELP

cmdline_parse_ctx_t main_ctx[] = {
    (cmdline_parse_inst_t*)&cmd_obj_acl_add,
    (cmdline_parse_inst_t*)&cmd_obj_lpm_lkp,
    (cmdline_parse_inst_t*)&cmd_obj_rlimit,
    (cmdline_parse_inst_t*)&cmd_obj_rlimit_net,
    (cmdline_parse_inst_t*)&cmd_stats,
    (cmdline_parse_inst_t*)&cmd_loglevel,
    (cmdline_parse_inst_t*)&cmd_logtype,
    (cmdline_parse_inst_t*)&pktj_cmd_loglevel_show,
    (cmdline_parse_inst_t*)&cmd_neigh,
    (cmdline_parse_inst_t*)&cmd_stats_json,
    (cmdline_parse_inst_t*)&cmd_stats_csv,
    (cmdline_parse_inst_t*)&cmd_showport,
    (cmdline_parse_inst_t*)&cmd_showport_json,
    (cmdline_parse_inst_t*)&cmd_config_rss,
    (cmdline_parse_inst_t*)&cmd_config_rss_reta,
    (cmdline_parse_inst_t*)&cmd_showport_reta,
    (cmdline_parse_inst_t*)&cmd_showport_rss_hash,
    (cmdline_parse_inst_t*)&cmd_showport_rss_hash_key,
    (cmdline_parse_inst_t*)&cmd_config_rss_hash_key,
    (cmdline_parse_inst_t*)&cmd_help,
    (cmdline_parse_inst_t*)&cmd_lpm_stats,
    (cmdline_parse_inst_t*)&cmd_lpm_stats_json,
//    (cmdline_parse_inst_t*)&cmd_dump_lpm,
    (cmdline_parse_inst_t*)&cmd_dump_neigh,
    NULL,
};

static int
create_unixsock(const char* path)
{
	int sock;
	struct sockaddr_un local;
	unsigned len;

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		RTE_LOG(ERR, CMDLINE1, "failed to create cmdline unixsock: %s",
			strerror(errno));
		goto err;
	}

	local.sun_family = AF_UNIX;
	strncpy(local.sun_path, path, sizeof(local.sun_path) - 1);
	local.sun_path[sizeof(local.sun_path) - 1] = '\0';
	unlink(local.sun_path);
	len = strlen(local.sun_path) + sizeof(local.sun_family);

	if (bind(sock, (struct sockaddr*)&local, len) == -1) {
		RTE_LOG(ERR, CMDLINE1, "failed to bind cmdline unixsock: %s",
			strerror(errno));
		goto err;
	}

	if (listen(sock, 10) == -1) {
		RTE_LOG(
		    ERR, CMDLINE1,
		    "failed to put the cmdline unixsock in listen state: %s",
		    strerror(errno));
		goto err;
	}

	return sock;
err:
	if (sock != -1)
		close(sock);
	return -1;
}

static struct cmdline*
cmdline_unixsock_new(cmdline_parse_ctx_t* ctx, const char* prompt, int sock)
{
	return (cmdline_new(ctx, prompt, sock, sock));
}

static void*
cmdline_new_unixsock(int sock)
{
	struct cmdline* cl;

	cl = cmdline_unixsock_new(main_ctx, "fpr> ", sock);

	if (cl == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create cmdline instance\n");

	return cl;
}

int
pktj_cmdline_init(const char* path, uint32_t socket_id)
{
	int fd;
	char buf[108];

	/* everything else is checked in cmdline_new() */
	if (!path)
		return -1;

	snprintf(buf, sizeof(buf), "%s.%d", path, socket_id);

	fd = create_unixsock(buf);
	if (fd < 0) {
		RTE_LOG(ERR, CMDLINE1, "create_unixsock() failed\n");
		return -1;
	}

	if (socket_id == 0) {
		if (symlink(buf, path) < 0) {
			RTE_LOG(WARNING, CMDLINE1, "symlink() failed %s\n",
				strerror(errno));
		}
	}

	if (socket_id >= NB_SOCKETS) {
		RTE_LOG(ERR, CMDLINE1, "Invalid socket_id\n");
		return -1;
	}

	cmdline_thread_unixsock[socket_id] = fd;

	memset(&cmdline_clients[socket_id], 0,
	       sizeof(cmdline_clients[socket_id]));
	return 0;
}

static int
pktj_cmdline_free(void* cmdline)
{
	struct cmdline* cl = cmdline;
	// cmdline_thread_loop = 0;

	cmdline_quit(cl);
	cmdline_free(cl);
	return 0;
}

int
pktj_cmdline_terminate(int sock, const char* path)
{
	int ret = 0;  // here for silence write warning
	char buf[128];

	if (pthread_join(cmdline_tid[sock], NULL)) {
		RTE_LOG(ERR, CMDLINE1,
			"error during free cmdline pthread_join: %s",
			strerror(errno));
	}
	close(cmdline_thread_unixsock[sock]);
	if (sock == 0) {
		unlink(path);
	}
	snprintf(buf, sizeof(buf), "%s.%d", path, sock);
	unlink(buf);
	return ret;
}

int
pktj_cmdline_stop(int sock)
{
	cmdline_thread_loop[sock] = 0;
	return 0;
}

static int
cmdline_clients_get(int sock)
{
	int j;
	for (j = 0; j < CMDLINE_MAX_CLIENTS; j++) {
		if (cmdline_clients[RTE_PER_LCORE(g_socket_id)][j].cl &&
		    cmdline_clients[RTE_PER_LCORE(g_socket_id)][j].s_in ==
			sock) {
			return j;
		}
	}
	rte_panic("cmdline_clients table desync");
	return -1;
}

static void
cmdline_clients_close(int id)
{
	pktj_cmdline_free(cmdline_clients[RTE_PER_LCORE(g_socket_id)][id].cl);
	close(cmdline_clients[RTE_PER_LCORE(g_socket_id)][id].s_out);
	memset(&cmdline_clients[RTE_PER_LCORE(g_socket_id)][id], 0,
	       sizeof(struct client_data_t));
	RTE_LOG(INFO, CMDLINE1, "Client id %d disconnected \n", id);
}

static void*
cmdline_run(void* data)
{
	struct pollfd
	    fds[CMDLINE_MAX_CLIENTS + 1];  // +1 for the listenning sock
	RTE_PER_LCORE(g_socket_id) = (intptr_t)data;
	int nfds = 1;
	int i, j, ret = 0;

	fds[0].events = POLLIN;
	fds[0].fd = cmdline_thread_unixsock[RTE_PER_LCORE(g_socket_id)];
	while (cmdline_thread_loop[RTE_PER_LCORE(g_socket_id)]) {
		int res = poll(fds, nfds, CMDLINE_POLL_TIMEOUT);
		if (res < 0) {
			if (errno == EINTR)
				break;
			RTE_LOG(ERR, CMDLINE1,
				"error during cmdline_run poll: %s",
				strerror(errno));
			return 0;
		}
		if (fds[0].revents & POLLIN) {
			res = accept(fds[0].fd, NULL, NULL);
			if (res < 0) {
				RTE_LOG(ERR, CMDLINE1,
					"error during cmdline_run accept: %s",
					strerror(errno));
				break;
			}
			for (i = 0; i < CMDLINE_MAX_CLIENTS; i++) {
				if (cmdline_clients[RTE_PER_LCORE(g_socket_id)]
						   [i].cl == NULL) {
					cmdline_clients[RTE_PER_LCORE(
					    g_socket_id)]
						       [i].cl =
					    cmdline_new_unixsock(res);
					cmdline_clients[RTE_PER_LCORE(
					    g_socket_id)]
						       [i].s_in = res;
					cmdline_clients[RTE_PER_LCORE(
					    g_socket_id)]
						       [i].s_out = res;

					break;
				}
			}

			if (i == CMDLINE_MAX_CLIENTS) {
#define CMDLINE_MCLI_MSG "Max client reached... \n"
				ret = send(res, CMDLINE_MCLI_MSG,
					   sizeof(CMDLINE_MCLI_MSG),
					   MSG_NOSIGNAL);
				close(res);
			}
		}

		for (i = 1; i < nfds; ++i) {
			if (fds[i].revents & (POLLIN | POLLHUP)) {
				char buf[64];

				j = cmdline_clients_get(fds[i].fd);
				ret = read(fds[i].fd, buf, sizeof(buf));
				// read error, closing conn
				if (ret <= 0) {
					cmdline_clients_close(j);
					continue;
				}
				// read error, closing conn
				ret = cmdline_in(
				    cmdline_clients[RTE_PER_LCORE(g_socket_id)]
						   [j].cl,
				    buf, ret);
				if (ret < 0 ) {
					printf("cmdline_in fails, so closing it\n");
					cmdline_clients_close(j);
				}
			}
		}

		nfds = 1;
		for (i = 0; i < CMDLINE_MAX_CLIENTS; i++) {
			if (cmdline_clients[RTE_PER_LCORE(g_socket_id)][i].cl) {
				if (cmdline_clients[RTE_PER_LCORE(g_socket_id)]
						   [i].csv_delay) {
					if ((time(NULL) -
					     cmdline_clients[RTE_PER_LCORE(
						 g_socket_id)]
							    [i].delay_timer) >=
					    cmdline_clients[RTE_PER_LCORE(
						g_socket_id)]
							   [i].csv_delay) {
						pktj_stats_display(
						    cmdline_clients
							[RTE_PER_LCORE(
							    g_socket_id)]
							[i].cl,
						    2, cmdline_clients
							   [RTE_PER_LCORE(
							       g_socket_id)]
							   [i].csv_delay);
					}
				}

				fds[nfds].fd =
				    cmdline_clients[RTE_PER_LCORE(g_socket_id)]
						   [i].s_in;
				fds[nfds].events = POLLIN;
				nfds++;
			}
		}
	}

	for (i = 0; i < CMDLINE_MAX_CLIENTS; i++) {
		if (cmdline_clients[RTE_PER_LCORE(g_socket_id)][i].cl) {
#define CMDLINE_QUIT_MSG "PKTJ closing...\n"
			ret = write(cmdline_clients[RTE_PER_LCORE(g_socket_id)]
						   [i].s_out,
				    CMDLINE_QUIT_MSG, sizeof(CMDLINE_QUIT_MSG));

			pktj_cmdline_free(
			    cmdline_clients[RTE_PER_LCORE(g_socket_id)][i].cl);

			shutdown(cmdline_clients[RTE_PER_LCORE(g_socket_id)]
						[i].s_out,
				 SHUT_RDWR);
			close(cmdline_clients[RTE_PER_LCORE(g_socket_id)]
					     [i].s_out);

			memset(&cmdline_clients[RTE_PER_LCORE(g_socket_id)][i],
			       0, sizeof(struct client_data_t));
		}
	}

	return 0;
}

pthread_t
pktj_cmdline_launch(int sock, cpu_set_t* cpuset)
{
	char thread_name[16];
	int ret;

	cmdline_thread_loop[sock] = 1;

	ret = pthread_create(&cmdline_tid[sock], NULL, cmdline_run,
			     (void*)(intptr_t)sock);
	if (ret != 0) {
		RTE_LOG(ERR, CMDLINE1, "failed to create cmdline thread: %s",
			strerror(errno));
		return -1;
	}

	snprintf(thread_name, 16, "cmdline-%d", sock);
	pthread_setname_np(cmdline_tid[sock], thread_name);

	ret = pthread_setaffinity_np(cmdline_tid[sock], sizeof(cpu_set_t),
				     cpuset);
	if (ret != 0) {
		RTE_LOG(ERR, CMDLINE1,
			"failed to call pthread_setaffinity_np: %s",
			strerror(errno));
		return -1;
	}

	return 0;
}
