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

#include "ipr_client.h"
#include "log.h"
#include "nl_rdma.h"

static int cells_used = 0;
struct cell_req pending[DEFAULT_PENDING_REQUESTS] = {};
pthread_mutex_t lock_pending = PTHREAD_MUTEX_INITIALIZER;
static int timeout_in_seconds = IP2GID_TIMEOUT_WAIT;
static int timeout_in_pending_list = IP2GID_PENDING_TIMEOUT;

int ipr_client_create(struct nl_ip2gid *ipr)
{
	struct timeval tv;
	int reuse = 1;
	int err = 0;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd >= 0)
		ipr->sockfd_c_ip4 = sockfd;
	else
		return errno;

	tv.tv_sec = timeout_in_seconds;
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

	return 0;

free_sock_c_ip4:
	close(ipr->sockfd_c_ip4);
	ipr->sockfd_c_ip4 = -1;

	return err;
}

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
		return EINVAL;
	}

	return ret;
}

static int client_nl_rdma_process_ip(const struct nl_msg *nl_req,
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
		    timeout_in_pending_list)
			free_cell_req(&pending[i]);

	}
	ip2gid_log_warn("Have %d cells used out of: %d\n",
			cells_used, DEFAULT_PENDING_REQUESTS);
}

static int client_send_ipr_req(const struct nl_ip2gid *ipr,
			       const struct nl_msg *nl_req,
			       const struct ip2gid_obj *req,
			       union addr_sa *req_addr,
			       socklen_t req_addr_size)
{
	struct cell_req *pending;
	int err = 0, sz;

	pthread_mutex_lock(&lock_pending);
	clear_timeout_cell_req();
	pending = find_cell_req();
	if (!pending) {
		pthread_mutex_unlock(&lock_pending);
		ip2gid_log_warn("Couldn't find free cell, drop kernel request (seq = %u)\n",
				nl_req->nlmsg_hdr.nlmsg_seq);
		return EBUSY;
	}

	pending->type = nl_req->nlmsg_hdr.nlmsg_type;
	pending->seq = nl_req->nlmsg_hdr.nlmsg_seq;
	ip2gid_log_dbg("Sending (msg_id = %u) request\n", pending->seq);

	sz = sendto(ipr->sockfd_c_ip4,
		     req->data, req->data_len, 0,
		     &req_addr->sa, req_addr_size);

	if (sz != req->data_len) {
		ip2gid_log_err("Didn't send all data on wire(msg_id = %u), sent %d expect %d\n",
			       pending->seq, sz, req->data_len);
		free_cell_req(pending);
		err = errno;
	}

	pthread_mutex_unlock(&lock_pending);
	return err;
}

int ipr_resolve_req(const struct nl_ip2gid *ipr, const struct nl_msg *nl_req)
{
	struct ip2gid_obj req = {};
	struct ip2gid_hdr *req_hdr;
	socklen_t addr_size;
	union addr_sa addr;
	struct cell_req *pnd;
	int err;

	if ((nl_req->nlmsg_hdr.nlmsg_len - NLMSG_HDRLEN) <
	    (sizeof(struct rdma_ls_ip_resolve_header) +
	     sizeof(struct nlattr)))
		return EINVAL;

	err = client_nl_rdma_process_ip(nl_req, &addr, &addr_size,
					&req, ipr->server_port);

	if (err) {
		ip2gid_log_err("process_ip failed %d", err);
		return EINVAL;
	}

	pthread_mutex_lock(&lock_pending);
	clear_timeout_cell_req();
	pnd = find_cell_req_seq(nl_req->nlmsg_hdr.nlmsg_seq);
	if (pnd) {
		pthread_mutex_unlock(&lock_pending);
		ip2gid_log_warn("Got a request(seq = %u) that is already pending, dropping\n",
				nl_req->nlmsg_hdr.nlmsg_seq);
		return EEXIST;
	}
	pthread_mutex_unlock(&lock_pending);

	req.data_len += sizeof(*req_hdr);
	req_hdr = (struct ip2gid_hdr *)req.data;
	req_hdr->version = htons(IP2GID_CURRENT_VERSION);
	req_hdr->msg_id = htonl(nl_req->nlmsg_hdr.nlmsg_seq);
	req_hdr->num_tlvs = htons(req_hdr->num_tlvs);

	return client_send_ipr_req(ipr, nl_req, &req, &addr, addr_size);
}

static void client_nl_rdma_send_resp(struct nl_ip2gid *priv,
				     struct cell_req *orig_req,
				     struct ip2gid_hdr *resp_hdr)
{
	struct ip2gid_resp_gid *gid_resp;
	struct nl_msg resp_msg = {};
	struct nlattr *attr;

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

	nl_rdma_send_resp(&resp_msg);
}

void *run_ipr_client(void *arg)
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
		ip2gid_log_warn("Got msg (msg_id = %u) which isn't pending\n",
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
