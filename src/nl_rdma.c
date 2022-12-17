/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2022 NVIDIA CORPORATION. All rights reserved
 */

#include <errno.h>
#include <pthread.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <rdma/rdma_netlink.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "log.h"
#include "ipr_client.h"
#include "path_resolve.h"

static int sock_nl_fd;

#define NL_RDMA_SOCKET_RCVBUF (2 * 1024 * 1024)

static int nl_rdma_init(void)
{
	struct sockaddr_nl saddr = {};
	int err, rcvbuf;
	socklen_t len = sizeof(rcvbuf);

	sock_nl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_RDMA);
	if (sock_nl_fd < 0)
		return errno;

	saddr.nl_family = AF_NETLINK;
	saddr.nl_pid = getpid();
	saddr.nl_groups = (1 << (RDMA_NL_GROUP_LS - 1));

	err = bind(sock_nl_fd, (struct sockaddr *)&saddr, sizeof(saddr));
	if (err < 0) {
		err = errno;
		goto fail_bind;
	}

	err = getsockopt(sock_nl_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, &len);
	if (err) {
		nl_log_warn("Get SO_RCVBUF failed errno %d\n", errno);
		return 0;
	}

	nl_log_info("NL_RDMA socket: default SO_RCVBUF 0x%x\n", rcvbuf);
	if (rcvbuf < NL_RDMA_SOCKET_RCVBUF) {
		rcvbuf = NL_RDMA_SOCKET_RCVBUF;
		err = setsockopt(sock_nl_fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, len);
		if (err) {
			nl_log_warn("NL_RDMA socket: Failed to set SO_RCVBUF to 0x%x\n", rcvbuf);
			return 0;
		}

		nl_log_info("NL_RDMA socket: Set SO_RCVBUF to 0x%x\n", rcvbuf);
	}

	return 0;

fail_bind:
	close(sock_nl_fd);
	return err;
}

static int nl_rdma_recv(struct nl_msg *req)
{
	int len;

	len = recv(sock_nl_fd, req, sizeof(*req), 0);
	if (len < 0)
		return errno;

	if (!NLMSG_OK(&req->nlmsg_hdr, len)) {
		nl_log_err("Invalid message: Expected length %d, received %d\n",
			   req->nlmsg_hdr.nlmsg_len, len);
		return EINVAL;
	}

	return 0;
}

static void nl_send_bad_resp(struct nl_msg *nl_req)
{
	struct sockaddr_nl dst_addr = {};
	struct nl_msg resp_msg = {};
	int datalen;
	int ret;

	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_groups = (1 << (RDMA_NL_GROUP_LS - 1));

	resp_msg.nlmsg_hdr.nlmsg_len = NLMSG_HDRLEN;
	resp_msg.nlmsg_hdr.nlmsg_pid = getpid();
	resp_msg.nlmsg_hdr.nlmsg_type = nl_req->nlmsg_hdr.nlmsg_type;
	resp_msg.nlmsg_hdr.nlmsg_seq = nl_req->nlmsg_hdr.nlmsg_seq;

	resp_msg.nlmsg_hdr.nlmsg_flags |= RDMA_NL_LS_F_ERR;

	datalen = NLMSG_ALIGN(resp_msg.nlmsg_hdr.nlmsg_len);
	ret = sendto(sock_nl_fd, &resp_msg, datalen, 0,
		     (void *)&dst_addr,
		     (socklen_t)sizeof(dst_addr));
	if (ret != datalen)
		nl_log_err("Response wasn't sent to kernel in full\n");
}

static void *run_nl_rdma_listen(void *arg)
{
	struct ib_resolve *priv = arg;
	struct nl_msg req = {};
	uint16_t type, op;
	int err;

	nl_log_info("nl_rdma_listen thread started...\n");
loop:
	err = nl_rdma_recv(&req);
	if (err) {
		nl_log_err("nl_rdma_recv failed %d, errno %d\n", err, errno);
		goto loop;
	}

	type = RDMA_NL_GET_CLIENT(req.nlmsg_hdr.nlmsg_type);
	if (type != RDMA_NL_LS) {
		nl_log_err("Unknown netlink msg type %d\n");
		goto loop;
	}

	op = RDMA_NL_GET_OP(req.nlmsg_hdr.nlmsg_type);
	nl_log_dbg("Got a new kernel request seq %u type %d op %d\n",
		   req.nlmsg_hdr.nlmsg_seq, type, op);
	switch (op) {
	case RDMA_NL_LS_OP_RESOLVE:
		err = path_resolve_req(&req);
		if (err)
			nl_log_err("Failed to do path_resolve\n");
		break;

	case RDMA_NL_LS_OP_IP_RESOLVE:
		err = ipr_resolve_req(&priv->ipr, &req);
		if (err)
			nl_log_err("Failed to handle nlmsg type %d op %d\n",
				   type, op);
		break;
	default:
		nl_log_err("Unable to handle nlmsg type %d op %d\n", type, op);
		nl_send_bad_resp(&req);
		break;
	}

	goto loop;

	return NULL;
}

int start_nl_rdma(struct ib_resolve *priv)
{
	int err;

	err = nl_rdma_init();
	if (err)
		return err;

	err = pthread_create(&priv->tid_nl_rdma, NULL, run_nl_rdma_listen, priv);
	if (err)
		goto out;

	return 0;

out:
	close(sock_nl_fd);
	return err;
}

int nl_rdma_send_resp(struct nl_msg *msg)
{
	struct sockaddr_nl dst = {};
	int data_len, ret;

	dst.nl_family = AF_NETLINK;
	dst.nl_groups = (1 << (RDMA_NL_GROUP_LS - 1));

	data_len = NLMSG_ALIGN(msg->nlmsg_hdr.nlmsg_len);
	ret = sendto(sock_nl_fd, msg, data_len,
		     0, (void *)&dst, (socklen_t)sizeof(dst));
	if (ret != data_len)
		ip2gid_log_err("Response wasn't sent to kernel in full\n");

	return ret;
}
