/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */
#ifndef _IB_RESOLVE_H
#define _IB_RESOLVE_H

#include <infiniband/sa.h>
#include <linux/rtnetlink.h>
#include <netlink/netlink.h>
#include <rdma/rdma_netlink.h>

#include "msg_spec.h"

#include "config.h"

#define IP2GID_SERVER_PORT 4791
#define IP2GID_TIMEOUT_WAIT 2
#define DEFAULT_PENDING_REQUESTS 1000

#define IBR_NL_MAX_PAYLOAD 512

struct ip2gid_obj {
	uint32_t data_len;
	char *data[sizeof(struct ip2gid_hdr) +
		sizeof(struct ip2gid_req_ipv4) +
		sizeof(struct ip2gid_resp_gid)];
};

#define NLA_LEN(nla) ((nla)->nla_len - NLA_HDRLEN)
#define NLA_DATA(nla) ((char *)(nla) + NLA_HDRLEN)

struct nl_msg {
	struct nlmsghdr nlmsg_hdr;
	union {
		uint8_t data[IBR_NL_MAX_PAYLOAD];
		struct rdma_ls_resolve_header rheader;
		struct nlattr attr[0];
	};
};

union addr_sa {
	struct sockaddr sa;
	struct sockaddr_in s4;
};

struct cell_req {
	uint8_t used;

	struct ip2gid_obj req;
	union addr_sa addr;
	socklen_t addr_size;

	uint32_t seq;
	uint16_t type;

	struct timespec stamp;
	uint32_t resend_num;
};

struct nl_ip2gid {
	int sockfd_c_ip4;
	int sockfd_s_ip4;
	unsigned int server_port;
	struct nl_sock* nl_sock;
};

struct ib_resolve {
	struct nl_ip2gid ipr;
	pthread_t tid_ipr_client;
	pthread_t tid_ipr_server;
	pthread_t tid_path_resolve;
	pthread_t tid_nl_rdma;
};

int msg_length_check(struct ip2gid_obj *obj, uint32_t max_len);
#endif	/* _IB_RESOLVE_H */
