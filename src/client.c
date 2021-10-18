/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <rdma/rdma_netlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "client.h"
#include "log.h"

static int cells_used = 0;
struct cell_req pending[DEFAULT_PENDING_REQUESTS] = {};
pthread_mutex_t lock_pending = PTHREAD_MUTEX_INITIALIZER;

int create_client(struct nl_ip2gid *priv)
{
	struct sockaddr_nl src_addr = {};
	struct timeval tv;
	int reuse = 1;
	int err = 0;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd >= 0)
		priv->sockfd_c_ip4 = sockfd;
	else
		return errno;

	tv.tv_sec = IP2GID_TIMEOUT_WAIT;
	tv.tv_usec = 0;
	if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO,
		       (const char*)&tv, sizeof(tv)) < 0) {
		err = errno;
		goto free_sock_c_ip4;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		       (const char*)&reuse, sizeof(reuse)) < 0) {
		err = errno;
		goto free_sock_c_ip4;
	}

#ifdef SO_REUSEPORT
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
		       (const char*)&reuse, sizeof(reuse)) < 0) {
		err = errno;
		goto free_sock_c_ip4;
	}
#endif

	sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_RDMA);
	if (sockfd < 0) {
		err = errno;
		goto free_sock_c_ip4;
	}

	priv->nl_rdma = sockfd;

	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = (1 << (RDMA_NL_GROUP_LS - 1));

	err = bind(priv->nl_rdma, (struct sockaddr *)&src_addr,
		   sizeof(src_addr));
	if (err < 0) {
		err = errno;
		goto free_nl_rdma;
	}

	return 0;

free_nl_rdma:
	close(priv->nl_rdma);
	priv->nl_rdma = -1;
free_sock_c_ip4:
	close(priv->sockfd_c_ip4);
	priv->sockfd_c_ip4 = -1;

	return err;
}

#define NLA_LEN(nla) ((nla)->nla_len - NLA_HDRLEN)
#define NLA_DATA(nla) ((char *)(nla) + NLA_HDRLEN)

static int client_nl_rdma_parse_ip_attr(struct nlattr *attr,
					union addr_sa *addr,
					socklen_t *addr_size,
					struct ip2gid_obj *hdr,
					unsigned int server_port)
{
	struct ip2gid_req_ipv4 *ipv4;
	struct ip2gid_hdr *req_hdr;
	int ret = 0;
	void *data;

	req_hdr = (struct ip2gid_hdr *)hdr->data;

	switch (attr->nla_type & RDMA_NLA_TYPE_MASK) {
	case LS_NLA_TYPE_IPV4:
		data = NLA_DATA(attr);
		addr->s4.sin_family = AF_INET;
		addr->s4.sin_port = htons(server_port);
		memcpy(&addr->s4.sin_addr.s_addr, data, 4);
		*addr_size = sizeof(addr->s4);

		ipv4 = (struct ip2gid_req_ipv4 *)req_hdr->tlvs;
		ipv4->hdr.type = htons(IP2GID_REQ_IPV4);
		ipv4->hdr.len = htons(sizeof(*ipv4));
		ipv4->ipv4 = addr->s4.sin_addr.s_addr;
		hdr->data_len += sizeof(*ipv4);
		req_hdr->num_tlvs++;
		break;

	default:
		return -EINVAL;
	}

	return ret;
}

static int client_nl_rdma_process_ip(struct nl_msg *nl_req,
				     union addr_sa *addr,
				     socklen_t *addr_size,
				     struct ip2gid_obj *req,
				     unsigned int server_port)
{
	unsigned char *data;
	struct nlattr *attr;
	int ip_res_hdr_len;
	int total_attr_len;
	int payload_len;
	int rem;
	int status;

	data = (unsigned char *) &nl_req->nlmsg_hdr + NLMSG_HDRLEN;
	ip_res_hdr_len = NLMSG_ALIGN(sizeof(struct rdma_ls_ip_resolve_header));
	attr = (struct nlattr *) (data + ip_res_hdr_len);
	payload_len = nl_req->nlmsg_hdr.nlmsg_len - NLMSG_HDRLEN -
		ip_res_hdr_len;

	rem = payload_len;
	while (1) {
		if (rem < (int) sizeof(*attr) ||
		    attr->nla_len < sizeof(*attr) ||
		    attr->nla_len > rem)
			break;

		status = client_nl_rdma_parse_ip_attr(attr, addr, addr_size,
						      req, server_port);
		if (status)
			return status;

		/* Next attribute */
		total_attr_len = NLA_ALIGN(attr->nla_len);
		rem -= total_attr_len;
		attr = (struct nlattr *) ((char *) attr + total_attr_len);
	}

	return status;
}

static void client_nl_send_bad_resp(struct nl_ip2gid *priv,
				    struct nl_msg *nl_req)
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
	ret = sendto(priv->nl_rdma, &resp_msg, datalen, 0,
		     (void *)&dst_addr,
		     (socklen_t)sizeof(dst_addr));
	if (ret != datalen)
		ip2gid_log(IP2GID_LOG_ERR,
			   "Response wasn't sent to kernel in full\n");
}

static void free_cell_req(struct cell_req *pending)
{
	memset(pending, 0, sizeof(*pending));
	cells_used--;
}

static struct cell_req *find_cell_req(void)
{
	int i;

	for (i = 0; i < DEFAULT_PENDING_REQUESTS; i++)
		if (!pending[i].used) {
			pending[i].used = 1;
			clock_gettime(CLOCK_REALTIME, &pending[i].stamp);
			cells_used++;
			return &pending[i];
		}

	return NULL;
}

static struct cell_req *find_cell_req_seq(uint32_t msg_id)
{
	int i;

	for (i = 0; i < DEFAULT_PENDING_REQUESTS; i++) {
		if (!pending[i].used)
			continue;
		if (pending[i].seq == msg_id)
			return &pending[i];
	}

	return NULL;
}

static void clear_timeout_cell_req(void)
{
	struct timespec finish;
	int i;

	clock_gettime(CLOCK_REALTIME, &finish);

	for (i = 0; i < DEFAULT_PENDING_REQUESTS; i++) {
		if (!pending[i].used)
			continue;
		if ((finish.tv_sec - pending[i].stamp.tv_sec) >
		    IP2GID_PENDING_TIMEOUT)
			free_cell_req(&pending[i]);

	}
	ip2gid_log(IP2GID_LOG_INFO,"Have %d cells used out of: %d\n",
		   cells_used, DEFAULT_PENDING_REQUESTS);
}

static int client_ip_recv(struct nl_ip2gid *priv,
			  union addr_sa *addr,
			  socklen_t *addr_size,
			  struct ip2gid_obj *req,
			  struct nl_msg *nl_req)
{
	struct ip2gid_hdr *req_hdr;
	struct cell_req *pending;
	uint16_t client_idx;
	uint16_t op;
	int err;

recv_again:
	memset(req, 0, sizeof(*req));
	memset(addr, 0, sizeof(*addr));
	memset(nl_req, 0, sizeof(*nl_req));
	err = recv(priv->nl_rdma, nl_req, sizeof(*nl_req), 0);
	if (err <= 0)
		goto recv_again;

	ip2gid_log(IP2GID_LOG_INFO, "Got a new kernel request\n");
        if (!NLMSG_OK(&nl_req->nlmsg_hdr, err))
                goto recv_again;

	client_idx = RDMA_NL_GET_CLIENT(nl_req->nlmsg_hdr.nlmsg_type);
        op = RDMA_NL_GET_OP(nl_req->nlmsg_hdr.nlmsg_type);
        if (client_idx != RDMA_NL_LS)
                goto recv_again;

	if (op != RDMA_NL_LS_OP_IP_RESOLVE) {
		client_nl_send_bad_resp(priv, nl_req);
		goto recv_again;
	}

	if ((nl_req->nlmsg_hdr.nlmsg_len - NLMSG_HDRLEN) <
	    (sizeof(struct rdma_ls_ip_resolve_header) +
	     sizeof(struct nlattr)))
		goto recv_again;

	err = client_nl_rdma_process_ip(nl_req, addr, addr_size,
					req, priv->server_port);

	if (err)
		goto recv_again;

	pthread_mutex_lock(&lock_pending);
	clear_timeout_cell_req();
	pending = find_cell_req_seq(nl_req->nlmsg_hdr.nlmsg_seq);
	if (pending) {
		pthread_mutex_unlock(&lock_pending);
		ip2gid_log(IP2GID_LOG_WARN,
			   "Got a request(seq = %u) that is already pending, dropping\n",
			   nl_req->nlmsg_hdr.nlmsg_seq);
		goto recv_again;
	}
	pthread_mutex_unlock(&lock_pending);

	req->data_len += sizeof(*req_hdr);
	req_hdr = (struct ip2gid_hdr *)req->data;
	req_hdr->version = htons(IP2GID_CURRENT_VERSION);
	req_hdr->msg_id = htonl(nl_req->nlmsg_hdr.nlmsg_seq);
	req_hdr->num_tlvs = htons(req_hdr->num_tlvs);

	return 0;
}

static void client_nl_rdma_send_resp(struct nl_ip2gid *priv,
				     struct cell_req *orig_req,
				     struct ip2gid_hdr *resp_hdr)
{
	struct sockaddr_nl dst_addr = {};
	struct ip2gid_resp_gid *gid_resp;
	struct nl_msg resp_msg = {};
	struct nlattr *attr;
	int datalen;
	int ret;

	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_groups = (1 << (RDMA_NL_GROUP_LS - 1));

	resp_msg.nlmsg_hdr.nlmsg_len = NLMSG_HDRLEN;
        resp_msg.nlmsg_hdr.nlmsg_pid = getpid();
	resp_msg.nlmsg_hdr.nlmsg_type = orig_req->type;
	resp_msg.nlmsg_hdr.nlmsg_seq = orig_req->seq;

	attr = resp_msg.attr;

	gid_resp = (struct ip2gid_resp_gid *)(resp_hdr->tlvs);

	attr->nla_type = LS_NLA_TYPE_DGID;
	attr->nla_len = NLA_ALIGN(sizeof(gid_resp->gid) + NLA_HDRLEN);

	memcpy(NLA_DATA(attr), gid_resp->gid,
	       sizeof(gid_resp->gid));
	resp_msg.nlmsg_hdr.nlmsg_len += attr->nla_len;

	datalen = NLMSG_ALIGN(resp_msg.nlmsg_hdr.nlmsg_len);
	ret = sendto(priv->nl_rdma, &resp_msg, datalen, 0,
		     (void *)&dst_addr,
		     (socklen_t)sizeof(dst_addr));
	if (ret != datalen)
		ip2gid_log(IP2GID_LOG_ERR,
			   "Response wasn't sent to kernel in full\n");
}

void *run_client_recv(void *arg)
{
	union addr_sa resp_addr = {};
	struct nl_ip2gid *priv = arg;
	struct ip2gid_obj resp = {};
	struct ip2gid_hdr *resp_hdr;
	socklen_t resp_addr_size;
	struct cell_req *_pending;
	struct cell_req pending;
	int sockfd;
	int err;

	resp_addr_size = sizeof(resp_addr.sa);
	sockfd = priv->sockfd_c_ip4;
loop:
	memset(&resp, 0, sizeof(resp));
	memset(&resp_addr, 0, sizeof(resp_addr));

	err = recvfrom(sockfd, resp.data, sizeof(resp.data),
		       MSG_WAITALL, &resp_addr.sa, &resp_addr_size);

	if (err <= 0)
		goto loop;

	if (msg_length_check(&resp, err))
		goto loop;

	resp.data_len = err;
	resp_hdr = (struct ip2gid_hdr *)resp.data;

	/* We support only GID response for now
	 * Ugly but works for now.
	 */
	if (ntohs(resp_hdr->num_tlvs) != 1 ||
	    ntohs(((struct ip2gid_tlv_hdr *)resp_hdr->tlvs)->type) !=
	    IP2GID_RESP_GID)
		goto loop;

	pthread_mutex_lock(&lock_pending);
	_pending = find_cell_req_seq(ntohl(resp_hdr->msg_id));
	if (!_pending) {
		pthread_mutex_unlock(&lock_pending);
		ip2gid_log(IP2GID_LOG_WARN,
			   "Got msg (msg_id = %u) which isn't pending\n",
			   ntohl(resp_hdr->msg_id));
		goto loop;
	}
	pending = *_pending;
	free_cell_req(_pending);
	pthread_mutex_unlock(&lock_pending);
	client_nl_rdma_send_resp(priv, &pending, resp_hdr);

	goto loop;

	return NULL;
}

void *run_client_send(void *arg)
{
	struct nl_ip2gid *priv = arg;
	union addr_sa req_addr = {};
	struct ip2gid_obj req = {};
	struct nl_msg nl_req = {};
	struct cell_req *pending;
	socklen_t req_addr_size;
	ssize_t err;
	int sockfd;

	sockfd = priv->sockfd_c_ip4;

loop:
	err = client_ip_recv(priv, &req_addr, &req_addr_size,
			     &req, &nl_req);
	if (err)
		goto loop;

	pthread_mutex_lock(&lock_pending);
	clear_timeout_cell_req();
	pending = find_cell_req();
	if (!pending) {
		pthread_mutex_unlock(&lock_pending);
		ip2gid_log(IP2GID_LOG_WARN,
			   "Couldn't find free cell, drop kernel request (seq = %u)\n",
			   nl_req.nlmsg_hdr.nlmsg_seq);
		goto loop;
	}

	pending->type = nl_req.nlmsg_hdr.nlmsg_type;
	pending->seq = nl_req.nlmsg_hdr.nlmsg_seq;
	ip2gid_log(IP2GID_LOG_INFO,
		   "Sending (msg_id = %u) request\n", pending->seq);

	err = sendto(sockfd,
		     req.data, req.data_len,
		     0,
		     &req_addr.sa, req_addr_size);

	if (err != req.data_len) {
		ip2gid_log(IP2GID_LOG_ERR,
			   "Didn't send all data on wire(msg_id = %u)\n",
			   pending->seq);
		free_cell_req(pending);
	}

	pthread_mutex_unlock(&lock_pending);
	goto loop;

	return NULL;
}
