/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */
#ifndef _IP2GID_H
#define _IP2GID_H

#include <linux/rtnetlink.h>
#include <netlink/netlink.h>

#include "msg_spec.h"

#include "config.h"

#define IP2GID_SERVER_PORT 4791
#define IP2GID_TIMEOUT_WAIT 2
#define IP2GID_NL_MAX_PAYLOAD 72
#define DEFAULT_PENDING_REQUESTS 500
#define IP2GID_PENDING_TIMEOUT 60

union addr_sa {
	struct sockaddr sa;
	struct sockaddr_in s4;
};

struct ip2gid_obj {
	uint32_t data_len;
	char *data[sizeof(struct ip2gid_hdr) +
		sizeof(struct ip2gid_req_ipv4) +
		sizeof(struct ip2gid_resp_gid)];
};

struct nl_msg {
	struct nlmsghdr nlmsg_hdr;
	union {
		uint8_t data[IP2GID_NL_MAX_PAYLOAD];
		struct nlattr attr[0];
	};
};

struct cell_req {
	char used;
	uint32_t seq;
	uint16_t type;
	struct timespec stamp;
};

struct nl_ip2gid {
	int sockfd_c_ip4;
	int sockfd_s_ip4;
	int  nl_rdma;
	unsigned int server_port;
	struct nl_sock* nl_sock;
};

#endif	/* _IP2GID_H */
