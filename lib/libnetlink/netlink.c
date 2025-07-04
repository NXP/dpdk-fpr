/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2024-2025 NXP
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

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <poll.h>
#include <rte_log.h>

#include "pktj_common.h"

#include "libnetlink.h"
#define NETL_POLL_TIMEOUT 1000

struct rte_ether_addr invalid_mac = { {0x00, 0x00, 0x00, 0x00, 0x00} };

static inline __u32 rta_getattr_u32(struct rtattr *rta)
{
	return *(__u32 *) RTA_DATA(rta);
}

static inline __u16 rta_getattr_u16(struct rtattr *rta)
{
	return *(__u16 *) RTA_DATA(rta);
}

static inline __u8 rta_getattr_u8(struct rtattr *rta)
{
	return *(__u8 *) RTA_DATA(rta);
}

static inline char *rta_getattr_str(struct rtattr *rta)
{
	return (char *) RTA_DATA(rta);
}

static inline int rtm_get_table(struct rtmsg *r, struct rtattr **tb)
{
	__u32 table = r->rtm_table;
	if (tb[RTA_TABLE])
		table = rta_getattr_u32(tb[RTA_TABLE]);
	return table;
}

#define parse_rtattr_nested(tb, max, rta) \
        (parse_rtattr_flags((tb), (max), RTA_DATA(rta), RTA_PAYLOAD(rta), 0))


static int parse_rtattr_flags(struct rtattr *tb[], int max,
							  struct rtattr *rta, int len,
							  unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
	if (len)
		fprintf(stderr, "!!!Deficit %d, rta_len=%d\n", len, rta->rta_len);
	return 0;
}

static uint16_t get_vlan_id(struct rtattr *linkinfo[])
{
	struct rtattr *vlaninfo[IFLA_VLAN_MAX + 1];
	if (!linkinfo[IFLA_INFO_DATA])
		return 0;
	parse_rtattr_nested(vlaninfo, IFLA_VLAN_MAX, linkinfo[IFLA_INFO_DATA]);
	if (vlaninfo[IFLA_VLAN_PROTOCOL]
		&& RTA_PAYLOAD(vlaninfo[IFLA_VLAN_PROTOCOL]) < sizeof(__u16))
		return 0;
	if (!vlaninfo[IFLA_VLAN_ID] ||
		RTA_PAYLOAD(vlaninfo[IFLA_VLAN_ID]) < sizeof(__u16))
		return 0;
	return rta_getattr_u16(vlaninfo[IFLA_VLAN_ID]);
}

static int
netl_handler(struct netl_handle *h,
			 pktj_unused(struct sockaddr_nl *nladdr),
			 struct nlmsghdr *hdr, void *args)
{
	int len = hdr->nlmsg_len;

	switch (hdr->nlmsg_type) {
		// TODO RTM_SETLINK
	case RTM_NEWLINK:
	case RTM_DELLINK:
		{
			struct ifinfomsg *ifi = NLMSG_DATA(hdr);
			struct rtattr *rta_tb[IFLA_MAX + 1];
			struct rte_ether_addr lladdr = {0};
			int ifid = ifi->ifi_index;
			int mtu = -1;
			const char *ifname = "";
			uint16_t vlanid = 0;
			oper_state_t state = LINK_UNKNOWN;
			link_action_t action = LINK_ADD;

			len -= NLMSG_LENGTH(sizeof(*ifi));

			if (len < 0) {
				h->cb.log("Bad length", RTE_LOG_DEBUG);
				return -1;
			}

			parse_rtattr_flags(rta_tb, IFLA_MAX, IFLA_RTA(ifi), len, 0);

			if (ifi->ifi_type != ARPHRD_ETHER)
				return 0;		// This is not ethernet
			if (rta_tb[IFLA_IFNAME] == NULL) {
				h->cb.log("No if name", RTE_LOG_DEBUG);
				return -1;		// There should be a name, this is a bug
			}
			if (hdr->nlmsg_type == RTM_DELLINK)
				action = LINK_DELETE;

			if (rta_tb[IFLA_MTU])
				mtu = *(int *) RTA_DATA(rta_tb[IFLA_MTU]);
			if (rta_tb[IFLA_IFNAME])
				ifname = rta_getattr_str(rta_tb[IFLA_IFNAME]);
			if (rta_tb[IFLA_OPERSTATE])
				state = rta_getattr_u8(rta_tb[IFLA_OPERSTATE]);
			if (rta_tb[IFLA_ADDRESS])
				memcpy(&lladdr.addr_bytes, RTA_DATA(rta_tb[IFLA_ADDRESS]),
					   sizeof(lladdr.addr_bytes));

			if (rta_tb[IFLA_LINKINFO]) {
				struct rtattr *linkinfo[IFLA_INFO_MAX + 1];
				parse_rtattr_nested(linkinfo, IFLA_INFO_MAX,
									rta_tb[IFLA_LINKINFO]);
				if (linkinfo[IFLA_INFO_KIND]) {
					char *kind = RTA_DATA(linkinfo[IFLA_INFO_KIND]);
					//XXX only handle vlan type for now
					if (!strcmp(kind, "vlan")) {
						vlanid = get_vlan_id(linkinfo);
					}
				}

			}

			if (h->cb.link != NULL) {
				h->cb.link(action, ifid, &lladdr, mtu,
						   ifname, state, vlanid, args);
			}

		}
		break;
	}


	if (hdr->nlmsg_type == RTM_NEWADDR || hdr->nlmsg_type == RTM_DELADDR) {
		struct rtattr *rta_tb[IFA_MAX + 1];
		struct ifaddrmsg *ifa = NLMSG_DATA(hdr);
		unsigned char buf_addr[sizeof(struct in6_addr)];
		addr_action_t action;
		len -= NLMSG_LENGTH(sizeof(*ifa));

		if (len < 0) {
			h->cb.log("Bad length", RTE_LOG_DEBUG);
			return -1;
		}

		if (hdr->nlmsg_type == RTM_NEWADDR)
			action = ADDR_ADD;
		else if (hdr->nlmsg_type == RTM_DELADDR)
			action = ADDR_DELETE;
		else {
			h->cb.log("Bad msg type", RTE_LOG_DEBUG);
			return -1;
		}

		parse_rtattr_flags(rta_tb, IFA_MAX, IFA_RTA(ifa), len, 0);

		if (!rta_tb[IFA_LOCAL])
			rta_tb[IFA_LOCAL] = rta_tb[IFA_ADDRESS];
		if (!rta_tb[IFA_ADDRESS])
			rta_tb[IFA_ADDRESS] = rta_tb[IFA_LOCAL];

		if (rta_tb[IFA_LOCAL]) {
			//we may optimize by passing directly RTA_DATA(rta_tb[IFA_LOCAL]) to the cb
			memcpy(buf_addr, RTA_DATA(rta_tb[IFA_LOCAL]),
				   RTA_PAYLOAD(rta_tb[IFA_LOCAL]));
		}
		switch (ifa->ifa_family) {
		case AF_INET:
			if (h->cb.addr4 != NULL) {
				h->cb.addr4(action, ifa->ifa_index,
							(struct in_addr *) buf_addr,
							ifa->ifa_prefixlen, args);
			}
			break;
		case AF_INET6:
			if (h->cb.addr6 != NULL) {
				h->cb.addr6(action, ifa->ifa_index,
							(struct in6_addr *) buf_addr,
							ifa->ifa_prefixlen, args);
			}
			break;
		default:
			h->cb.log("Bad protocol", RTE_LOG_DEBUG);
			return -1;
		}
	}

	if (hdr->nlmsg_type == RTM_NEWROUTE || hdr->nlmsg_type == RTM_DELROUTE) {
		struct rtattr *tb[RTA_MAX + 1];
		struct rtmsg *r = NLMSG_DATA(hdr);
		len -= NLMSG_LENGTH(sizeof(*r));

		if (len < 0) {
			h->cb.log("Bad length", RTE_LOG_DEBUG);
			return -1;
		}

		if (r->rtm_family != RTNL_FAMILY_IPMR &&
			r->rtm_family != RTNL_FAMILY_IP6MR) {
			// This is an unicast route, no interest for multicast
			route_action_t action;
			if (hdr->nlmsg_type == RTM_NEWROUTE)
				action = ROUTE_ADD;
			else
				action = ROUTE_DELETE;

			parse_rtattr_flags(tb, RTA_MAX, RTM_RTA(r), len, 0);

			switch(r->rtm_type) {
				case RTN_UNICAST:
					// null RTA_DST should only happen on default route
					if (!tb[RTA_DST] && r->rtm_dst_len)
						return 0;

					if (!tb[RTA_GATEWAY])
						return 0;
				case RTN_BLACKHOLE:
					break;
				default:
					return 0;
			}

			switch (r->rtm_family) {
			case AF_INET:
				if (h->cb.route4 != NULL) {
					h->cb.route4(r, action, RTA_DATA(tb[RTA_DST]),
								 r->rtm_dst_len, RTA_DATA(tb[RTA_GATEWAY]),
								 r->rtm_type, args);
				}
				break;
			case AF_INET6:
				if (h->cb.route6 != NULL) {
					h->cb.route6(r, action, RTA_DATA(tb[RTA_DST]),
								 r->rtm_dst_len, RTA_DATA(tb[RTA_GATEWAY]),
								 r->rtm_type, args);
				}
				break;
			default:
				h->cb.log("Bad protocol", RTE_LOG_DEBUG);
				return -1;
			}
		}
	}

	if (hdr->nlmsg_type == RTM_NEWNEIGH || hdr->nlmsg_type == RTM_DELNEIGH) {
		struct ndmsg *neighbor = NLMSG_DATA(hdr);
		struct rtattr *tb[NDA_MAX + 1];
		uint16_t vlanid = 0;

		len -= NLMSG_LENGTH(sizeof(*neighbor));

		if (len < 0) {
			h->cb.log("Bad length", RTE_LOG_DEBUG);
			return -1;
		}
		// Ignore non-ip
		if (neighbor->ndm_family != AF_INET &&
			neighbor->ndm_family != AF_INET6) {
			h->cb.log("Bad protocol", RTE_LOG_DEBUG);
			return 0;
		}
		parse_rtattr_flags(tb, NDA_MAX, RTM_RTA(neighbor), len, 0);

		neighbor_action_t action;
		if (hdr->nlmsg_type == RTM_NEWNEIGH)
			action = NEIGHBOR_ADD;
		else
			action = NEIGHBOR_DELETE;
		if (tb[NDA_VLAN])
			vlanid = rta_getattr_u16(tb[NDA_VLAN]);
		switch (neighbor->ndm_family) {
		case AF_INET:
			if (h->cb.neighbor4 != NULL) {
				if (tb[NDA_LLADDR]) {
					h->cb.neighbor4(action, neighbor->ndm_ifindex,
									RTA_DATA(tb[NDA_DST]),
									RTA_DATA(tb[NDA_LLADDR]),
									neighbor->ndm_state, vlanid, args);
				} else {
					h->cb.neighbor4(action, neighbor->ndm_ifindex,
									RTA_DATA(tb[NDA_DST]),
									&invalid_mac,
									neighbor->ndm_state, vlanid, args);
				}
			}
			break;
		case AF_INET6:
			if (h->cb.neighbor6 != NULL) {
				if (tb[NDA_LLADDR]) {
					h->cb.neighbor6(action, neighbor->ndm_ifindex,
									RTA_DATA(tb[NDA_DST]),
									RTA_DATA(tb[NDA_LLADDR]),
									neighbor->ndm_state, vlanid, args);
				} else {
					h->cb.neighbor6(action, neighbor->ndm_ifindex,
									RTA_DATA(tb[NDA_DST]),
									&invalid_mac,
									neighbor->ndm_state, vlanid, args);
				}
			}
			break;
		default:
			h->cb.log("Bad protocol", RTE_LOG_DEBUG);
			return -1;
		}
	}

	return 0;
}

int netl_close(struct netl_handle *h)
{
	h->closing = 1;
	return 0;
}

int netl_terminate(struct netl_handle *h)
{
	if (h->fd > 0) {
		close(h->fd);
	}
	return 0;
}

int netl_listen(struct netl_handle *h, void *args)
{
	int len, err;
	char logmsg[256];
	int msg_count;
	ssize_t status;
	struct nlmsghdr *hdr;
	struct sockaddr_nl nladdr;
	struct iovec iov;
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char buf[8192];
	struct pollfd fds[1];

	if (h == NULL)
		return -1;

	iov.iov_base = buf;

	if (h->cb.init != NULL) {
		err = h->cb.init(args);
		if (err != 0)
			return err;
	}
	fds[0].events = POLLIN;
	fds[0].fd = h->fd;

	while (h->closing != 1) {
		int res = poll(fds, 1, NETL_POLL_TIMEOUT);
		if (res < 0 && errno != EINTR) {
			h->cb.log("Error while polling netlink socket", RTE_LOG_ERR);
			continue;
		}

		if (fds[0].revents & POLLIN) {
			iov.iov_len = sizeof(buf);
			status = recvmsg(h->fd, &msg, 0);
			if (status < 0) {
				snprintf(logmsg, 256, "error receiving netlink %s (%d)",
						strerror(errno), errno);
				h->cb.log(logmsg, RTE_LOG_ERR);
				continue;
			}

			if (status == 0) {
				h->cb.log("EOF on netlink", RTE_LOG_ERR);
				return -1;
			}

			if (msg.msg_namelen != sizeof(nladdr)) {
				h->cb.log("Wrong address length", RTE_LOG_ERR);
				continue;
			}

			if (iov.iov_len < ((size_t) status) || (msg.msg_flags & MSG_TRUNC)) {
				h->cb.log("Malformatted or truncated message, skipping", RTE_LOG_ERR);
				continue;
			}

			msg_count = 0;
			h->cb.log("Parsing netlink msg", RTE_LOG_DEBUG);
			for (hdr = (struct nlmsghdr *) buf;
				 (size_t) status >= sizeof(*hdr);) {
				len = hdr->nlmsg_len;

				snprintf(logmsg, 256, "Processing netlink msg of %d length", len);
				h->cb.log(logmsg, RTE_LOG_DEBUG);

				err = netl_handler(h, &nladdr, hdr, args);
				if (err < 0)
					h->cb.log("netl_handler failed", RTE_LOG_ERR);

				msg_count++;
				status -= NLMSG_ALIGN(len);
				hdr =
					(struct nlmsghdr *) ((char *) hdr + NLMSG_ALIGN(len));
			}
			snprintf(logmsg, 256, "processed %d netlink msg in buffer",
					msg_count);
			h->cb.log(logmsg, RTE_LOG_DEBUG);

			if (status) {
				h->cb.log("Remnant data not read", RTE_LOG_ERR);
				continue;
			}
		}
	}

	return 1;
}

static inline __u32 nl_mgrp(__u32 group)
{
	return group ? (1 << (group - 1)) : 0;
}

struct netl_handle *netl_create(unsigned events)
{
	struct netl_handle *netl_handle;
	int rcvbuf = 1024 * 1024 * 1024;
	socklen_t addr_len;
	unsigned subscriptions = 0;

    switch (events) {
        case NETLINK4_EVENTS:
            subscriptions |= nl_mgrp(RTNLGRP_LINK);
            subscriptions |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
            subscriptions |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
            break;
        case NETLINK6_EVENTS:
            subscriptions |= nl_mgrp(RTNLGRP_IPV6_IFADDR);
            subscriptions |= nl_mgrp(RTNLGRP_IPV6_ROUTE);
            break;
        case NETLINK4_EVENTS | NETLINK6_EVENTS:
            subscriptions |= nl_mgrp(RTNLGRP_LINK);
            subscriptions |= nl_mgrp(RTNLGRP_IPV4_IFADDR);
            subscriptions |= nl_mgrp(RTNLGRP_IPV4_ROUTE);
            subscriptions |= nl_mgrp(RTNLGRP_IPV6_IFADDR);
            subscriptions |= nl_mgrp(RTNLGRP_IPV6_ROUTE);
    }
	subscriptions |= nl_mgrp(RTNLGRP_NEIGH);

	netl_handle =
		pktj_calloc("netl_handle", 1, sizeof(struct netl_handle), 0,
					 SOCKET_ID_ANY);
	if (netl_handle == NULL)
		return NULL;

	netl_handle->fd =
		socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
	if (netl_handle->fd < 0) {
		perror("Cannot open netlink socket");
		goto free_netl_handle;
	}

	if (setsockopt
		(netl_handle->fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf,
		 sizeof(rcvbuf)) < 0) {
		perror("Cannot set RCVBUF");
		goto free_netl_handle;
	}

	memset(&netl_handle->local, 0, sizeof(netl_handle->local));
	netl_handle->local.nl_family = AF_NETLINK;
	netl_handle->local.nl_groups = subscriptions;

	netl_handle->cb.neighbor4 = NULL;
	netl_handle->cb.route4 = NULL;

	if (bind
		(netl_handle->fd, (struct sockaddr *) &(netl_handle->local),
		 sizeof(netl_handle->local)) < 0) {
		perror("Cannot bind netlink socket");
		goto free_netl_handle;
	}

	addr_len = sizeof(netl_handle->local);
	if (getsockname
		(netl_handle->fd, (struct sockaddr *) &netl_handle->local,
		 &addr_len) < 0) {
		perror("Cannot getsockname");
		goto free_netl_handle;
	}

	if (addr_len != sizeof(netl_handle->local)) {
		perror("Wrong address length");
		goto free_netl_handle;
	}

	if (netl_handle->local.nl_family != AF_NETLINK) {
		perror("Wrong address family");
		goto free_netl_handle;
	}

	netl_handle->closing = 0;

	return netl_handle;

  free_netl_handle:
	pktj_free(netl_handle);
	return NULL;
}

int netl_free(struct netl_handle *h)
{
	if (h != NULL) {
		if (h->fd > 0) {
			close(h->fd);
			h->fd = -1;
		}

		pktj_free(h);
	}

	return 0;
}
