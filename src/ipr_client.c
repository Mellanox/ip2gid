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

#define RESEND_CHECK_INTERVAL  1000 /* ms */
#define RESEND_MAX_NUM  30

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

static void __free_cell_req(struct cell_req *pending)
{
	memset(pending, 0, sizeof(*pending));
	cells_used--;
}

static struct cell_req *__find_cell_req(void)
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

static struct cell_req *__find_cell_req_seq(uint32_t msg_id)
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

static int __client_send_ipr_req(const struct nl_ip2gid *ipr,
				 struct cell_req *pending)
{
	struct cell_req tmp = *pending;
	int err = 0, sz;

	pthread_mutex_unlock(&lock_pending);
	sz = sendto(ipr->sockfd_c_ip4,
		    tmp.req.data, tmp.req.data_len, 0,
		    &tmp.addr.sa, tmp.addr_size);

	if (sz != tmp.req.data_len) {
		ip2gid_log_err("Didn't send all data on wire(msg_id = %u), sent %d expect %d\n",
			       tmp.seq, sz, tmp.req.data_len);
		err = errno;
	}

	pthread_mutex_lock(&lock_pending);
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
		ip2gid_log_err("process_ip failed %d\n", err);
		return EINVAL;
	}

	pthread_mutex_lock(&lock_pending);
	pnd = __find_cell_req_seq(nl_req->nlmsg_hdr.nlmsg_seq);
	if (pnd) {
		ip2gid_log_warn("Got a request(seq = %u) that is already pending, resend %d\n",
				nl_req->nlmsg_hdr.nlmsg_seq, pnd->resend_num);
		/* Refresh the pending cell */
		clock_gettime(CLOCK_REALTIME, &pnd->stamp);
		pnd->resend_num = 0;
	} else {
		pnd = __find_cell_req();
		if (!pnd) {
			ip2gid_log_warn("Couldn't find free cell, drop kernel request seq = %u\n",
					nl_req->nlmsg_hdr.nlmsg_seq);
			err = EBUSY;
			goto out;
		}

		pnd->req = req;
		pnd->addr = addr;
		pnd->addr_size = addr_size;
		pnd->type = nl_req->nlmsg_hdr.nlmsg_type;
		pnd->seq = nl_req->nlmsg_hdr.nlmsg_seq;

		pnd->req.data_len += sizeof(*req_hdr);
		req_hdr = (struct ip2gid_hdr *)pnd->req.data;
		req_hdr->version = htons(IP2GID_CURRENT_VERSION);
		req_hdr->msg_id = htonl(nl_req->nlmsg_hdr.nlmsg_seq);
		req_hdr->num_tlvs = htons(req_hdr->num_tlvs);
	}

	/* No need to check error as there's resend mechanism */
	__client_send_ipr_req(ipr, pnd);

out:
	pthread_mutex_unlock(&lock_pending);
	return err;
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

static uint32_t time_diff_ms(struct timespec *a, struct timespec *b)
{
	return (b->tv_sec - a->tv_sec) * 1000 + (b->tv_nsec - a->tv_nsec) / 1000000;
}

static pthread_t tid_timeout;
void *run_check_timeout(void *arg)
{
	struct nl_ip2gid *ipr = arg;
	struct timespec now;
	int i;

	do {
		usleep(RESEND_CHECK_INTERVAL * 1000);
		clock_gettime(CLOCK_REALTIME, &now);

		pthread_mutex_lock(&lock_pending);

		if (!cells_used)
			goto next_round;

		for (i = 0; i < DEFAULT_PENDING_REQUESTS; i++) {
			if (!pending[i].used ||
			    time_diff_ms(&pending[i].stamp, &now) < RESEND_CHECK_INTERVAL)
				continue;

			if (pending[i].resend_num >= RESEND_MAX_NUM) {
				ip2gid_log_warn("Request %u is released due to timeout\n",
						pending[i].seq);
				__free_cell_req(&pending[i]);
				continue;
			}

			__client_send_ipr_req(ipr, &pending[i]);

			pending[i].stamp = now;
			pending[i].resend_num++;
			ip2gid_log_warn("Request %u resent %d times\n",
					pending[i].seq, pending[i].resend_num);
		}
next_round:
		pthread_mutex_unlock(&lock_pending);
	} while (1);

	return NULL;
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

	err = pthread_create(&tid_timeout, NULL, &run_check_timeout, priv);
	if (err) {
		ip2gid_log_err("Failed to create run_check_timeout thread %d", errno);
		exit(1);
	}

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
	_pending = __find_cell_req_seq(ntohl(resp_hdr->msg_id));
	if (!_pending) {
		pthread_mutex_unlock(&lock_pending);
		ip2gid_log_warn("Got msg (msg_id = %u) which isn't pending\n",
				ntohl(resp_hdr->msg_id));
		goto loop;
	}
	pending = *_pending;
	__free_cell_req(_pending);
	pthread_mutex_unlock(&lock_pending);
	client_nl_rdma_send_resp(priv, &pending, resp_hdr);

	goto loop;

	return NULL;
}
