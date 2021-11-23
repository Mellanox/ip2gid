/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2020 NVIDIA CORPORATION. All rights reserved
 */

#include <linux/if_infiniband.h>
#include <netlink/route/link.h>
#include <netlink/netlink.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <rdma/rdma_netlink.h>
#include <string.h>
#include <signal.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>
#include <stdarg.h>

#include <getopt.h>
#include <msg_spec.h>

#include "ip2gid.h"

#include "config.h"

#define IP2GID_LOG_FILE "stdout"

#define ip2gid_log(level, format, ...) \
	ip2gid_write(level, "%s: "format, __func__, ## __VA_ARGS__)

enum {
	IP2GID_LOG_ALL,
	IP2GID_LOG_INFO,
	IP2GID_LOG_WARN,
	IP2GID_LOG_ERR,
};

struct nl_ip2gid priv = {-1, -1, -1, 0, NULL};

static int cells_used = 0;
struct cell_req pending[DEFAULT_PENDING_REQUESTS] = {};
pthread_mutex_t lock_pending = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static int server_port = IP2GID_SERVER_PORT;
static int timeout_in_seconds = IP2GID_TIMEOUT_WAIT;
static int timeout_in_pending_list = IP2GID_PENDING_TIMEOUT;
static char log_file[128] = IP2GID_LOG_FILE;
static int log_level = IP2GID_LOG_ERR;
static FILE *flog;

static char *log_level_str(int level)
{
	if (level == IP2GID_LOG_INFO)
		return "INFO";
	if (level == IP2GID_LOG_WARN)
		return "WARN";
	if (level == IP2GID_LOG_ERR)
		return "ERR";

	return "UNKNOWN";
}

#define ip2gid_inet_ntop(level, ...) do {	\
	if (level < log_level)			\
		break;				\
	inet_ntop(__VA_ARGS__);			\
} while(0)

static void ip2gid_write(int level, const char *format, ...)
{
        va_list args;
        struct timeval tv;
        struct tm tmtime;
        char buffer[20];

        if (level < log_level)
                return;

        gettimeofday(&tv, NULL);
        localtime_r(&tv.tv_sec, &tmtime);
        strftime(buffer, 20, "%Y-%m-%dT%H:%M:%S", &tmtime);
        va_start(args, format);
        pthread_mutex_lock(&log_lock);
        fprintf(flog, "%s.%03u:%s: ",
		buffer,
		(unsigned) (tv.tv_usec / 1000),
		log_level_str(level));
        vfprintf(flog, format, args);
        fflush(flog);
        pthread_mutex_unlock(&log_lock);
        va_end(args);
}

static FILE *ip2gid_open_log(void)
{
        FILE *f;

        if (!strcasecmp(log_file, "stdout"))
                return stdout;

        if (!strcasecmp(log_file, "stderr"))
                return stderr;

        if (!(f = fopen(log_file, "w")))
                f = stdout;

        return f;
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
	ip2gid_log(IP2GID_LOG_INFO,"Have %d cells used out of: %d\n",
		   cells_used, DEFAULT_PENDING_REQUESTS);
}

static int msg_length_check(struct ip2gid_obj *obj, uint32_t max_len)
{
	struct ip2gid_tlv_hdr *tlv;
	struct ip2gid_hdr *hdr;
	uint16_t num_tlvs;

	if (max_len <= sizeof(struct ip2gid_hdr)) {
		ip2gid_log(IP2GID_LOG_INFO,
			   "Msg length too short\n");
		return -1;
	}

	hdr = (struct ip2gid_hdr *)obj->data;
	ip2gid_log(IP2GID_LOG_INFO,
		   "Checking new Msg (msg_id = %u)\n",
		   ntohl(hdr->msg_id));
	num_tlvs = ntohs(hdr->num_tlvs);
	if (!num_tlvs) {
		ip2gid_log(IP2GID_LOG_INFO,
			   "\tNo TLVS in Msg\n");
		return -1;
	}

	ip2gid_log(IP2GID_LOG_INFO, "\tNum tlvs:%u\n", num_tlvs);
	if (hdr->version > IP2GID_CURRENT_VERSION) {
		ip2gid_log(IP2GID_LOG_INFO,
			   "\tMsg version isn't supported\n");
		return -1;
	}

	max_len -= sizeof(struct ip2gid_hdr);

	tlv = (struct ip2gid_tlv_hdr *)hdr->tlvs;
	while (num_tlvs && max_len >= 0) {
		uint16_t tlv_len = ntohs(tlv->len);

		max_len -= tlv_len;
		switch (ntohs(tlv->type)) {
		case IP2GID_REQ_NONE:
			if (tlv_len != sizeof(struct ip2gid_tlv_hdr)) {
				ip2gid_log(IP2GID_LOG_INFO,
					   "\tTLV: None: invalid length (len= %u)\n",
					   tlv_len);
				return -1;
			}
			break;
		case IP2GID_REQ_IPV4:
			if (tlv_len != sizeof(struct ip2gid_req_ipv4)) {
				ip2gid_log(IP2GID_LOG_INFO,
					   "\tTLV: IPV4: invalid length (len = %u)\n",
					   tlv_len);
				return -1;
			}
			break;
		case IP2GID_RESP_GID:
			if (tlv_len != sizeof(struct ip2gid_resp_gid)) {
				ip2gid_log(IP2GID_LOG_INFO,
					   "\tTLV: GID: invalid length (len = %u)\n",
					   tlv_len);
				return -1;
			}
			break;
		default:
			ip2gid_log(IP2GID_LOG_INFO,
				   "\tTLV: Unknown type\n");
			return -1;
		}
		tlv = (struct ip2gid_tlv_hdr *)((char *)tlv + tlv_len);
		num_tlvs--;
	}
	if (num_tlvs == 0 && max_len >= 0) {
		ip2gid_log(IP2GID_LOG_INFO,
			   "\tMsg passed basic checks\n");
		return 0;
	}

	return -1;
}

static int server_find_gid(struct ip2gid_req_ipv4 *req,
			   struct ip2gid_hdr *resp_hdr,
			   struct ip2gid_resp_gid *resp,
			   uint32_t *resp_len)
{
	char gid_str[INET6_ADDRSTRLEN] = {};
	char ip_str[INET_ADDRSTRLEN] = {};
	struct nl_addr *nl_addr;
	struct rtnl_link *link;
	struct ifaddrs* ifaddr;
	struct ifaddrs* ifa;
	int err;

	ip2gid_inet_ntop(IP2GID_LOG_INFO, AF_INET, (const void *)(&req->ipv4),
			 ip_str, sizeof(ip_str));
	ip2gid_log(IP2GID_LOG_INFO,
		   "Requesting GID for ip: %s\n", ip_str);
	err = getifaddrs(&ifaddr);
	if (err)
		return err;
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr &&
		    ifa->ifa_addr->sa_family == AF_INET) {
			struct sockaddr_in* inaddr;

			inaddr = (struct sockaddr_in*)ifa->ifa_addr;
			if (inaddr->sin_addr.s_addr == req->ipv4 &&
			    ifa->ifa_name)
				goto done;
		}
	}

done:
	if (ifa && ifa->ifa_name) {
		err = rtnl_link_get_kernel(priv.nl_sock, 0, ifa->ifa_name,
					   &link);
		if (err)
			goto free_faddrs;
		nl_addr = rtnl_link_get_addr(link);
		if (nl_addr) {
			if (nl_addr_get_len(nl_addr) == INFINIBAND_ALEN) {
				memcpy(resp->gid,
				       nl_addr_get_binary_addr(nl_addr) + 4,
				       16);
				resp->hdr.type = htons(IP2GID_RESP_GID);
				resp->hdr.len = htons(sizeof(*resp));
				(*resp_len) += sizeof(*resp);
				resp_hdr->num_tlvs++;
				ip2gid_inet_ntop(IP2GID_LOG_INFO,
						 AF_INET6,
						 resp->gid, gid_str,
						 sizeof(gid_str));
				ip2gid_log(IP2GID_LOG_INFO,
					   "Found GID(%s) for request ip (%s)\n",
					   gid_str, ip_str);
                        } else {
				err = ENOENT;
			}
		} else {
			err = ENOENT;
		}
		rtnl_link_put(link);
	}
free_faddrs:
	freeifaddrs(ifaddr);

	return err;
}

static int server_fill_req(struct ip2gid_obj *req,
			   struct ip2gid_obj *resp)
{
	struct ip2gid_hdr *resp_hdr;
	struct ip2gid_hdr *req_hdr;
	int err;

	resp_hdr = (struct ip2gid_hdr *)resp->data;
	req_hdr = (struct ip2gid_hdr *)req->data;

	/* We support only IPV4 resolution for now
	 * Ugly but works for now.
	 */
	if (ntohs(req_hdr->num_tlvs) != 1 ||
	    ntohs(((struct ip2gid_tlv_hdr *)req_hdr->tlvs)->type) !=
	    IP2GID_REQ_IPV4)
		return -1;

	ip2gid_log(IP2GID_LOG_INFO,
		   "Got IP2GID request (msg_id = %u)\n",
		   ntohl(req_hdr->msg_id));
	err = server_find_gid((struct ip2gid_req_ipv4 *)req_hdr->tlvs, resp_hdr,
			      (struct ip2gid_resp_gid *)resp_hdr->tlvs,
			      &resp->data_len);
	if (err)
		return err;

	resp_hdr->version = req_hdr->version;
	resp_hdr->msg_id = req_hdr->msg_id;
	resp_hdr->num_tlvs = htons(resp_hdr->num_tlvs);
	resp->data_len += sizeof(*resp_hdr);
	ip2gid_log(IP2GID_LOG_INFO,
		   "Filled good response (msg_id = %u)\n",
		   ntohl(req_hdr->msg_id));

	return err;
}

static int create_server(void)
{
	struct sockaddr_in serv_addr = {};
	int reuse = 1;
	int err = 0;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd < 0)
		return errno;

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,
		       (const char*)&reuse, sizeof(reuse)) < 0) {
		err = errno;
		goto err_ip4;
	}

#ifdef SO_REUSEPORT
	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT,
		       (const char*)&reuse, sizeof(reuse)) < 0) {
		err = errno;
		goto err_ip4;
	}
#endif
	priv.sockfd_s_ip4 = sockfd;

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(server_port);

	err = bind(sockfd, (void *)&serv_addr, sizeof(serv_addr));
	if (err < 0) {
		err = errno;
		goto err_ip4;
	}

	priv.nl_sock = nl_socket_alloc();
	if (!priv.nl_sock)
		goto err_ip4;
	err = nl_connect(priv.nl_sock, NETLINK_ROUTE);
	if (err)
		goto free_sock;

	return err;

free_sock:
	nl_socket_free(priv.nl_sock);
	priv.nl_sock = NULL;
err_ip4:
	close(priv.sockfd_s_ip4);
	priv.sockfd_s_ip4 = -1;

	return err;
}

static int create_client(void)
{
	struct sockaddr_nl src_addr = {};
	struct timeval tv;
	int reuse = 1;
	int err = 0;
	int sockfd;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if (sockfd >= 0)
		priv.sockfd_c_ip4 = sockfd;
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

	sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_RDMA);
	if (sockfd < 0) {
		err = errno;
		goto free_sock_c_ip4;
	}

	priv.nl_rdma = sockfd;

	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = (1 << (RDMA_NL_GROUP_LS - 1));

	err = bind(priv.nl_rdma, (struct sockaddr *)&src_addr,
		   sizeof(src_addr));
	if (err < 0) {
		err = errno;
		goto free_nl_rdma;
	}

	return 0;

free_nl_rdma:
	close(priv.nl_rdma);
	priv.nl_rdma = -1;
free_sock_c_ip4:
	close(priv.sockfd_c_ip4);
	priv.sockfd_c_ip4 = -1;

	return err;
}

#define NLA_LEN(nla) ((nla)->nla_len - NLA_HDRLEN)
#define NLA_DATA(nla) ((char *)(nla) + NLA_HDRLEN)

static int client_nl_rdma_parse_ip_attr(struct nlattr *attr,
					union addr_sa *addr,
					socklen_t *addr_size,
					struct ip2gid_obj *hdr)
{
	char ip_str[INET_ADDRSTRLEN] = {};
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
		ip2gid_inet_ntop(IP2GID_LOG_INFO, AF_INET,
				 (const void *)(&ipv4->ipv4),
				 ip_str, sizeof(ip_str));
		ip2gid_log(IP2GID_LOG_INFO,
			   "Got KERNEL request ip2gid for ip: %s\n", ip_str);
		break;

	default:
		return -EINVAL;
	}

	return ret;
}

static int client_nl_rdma_process_ip(struct nl_msg *nl_req,
				     union addr_sa *addr,
				     socklen_t *addr_size,
				     struct ip2gid_obj *req)
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
						      req);
		if (status)
			return status;

		/* Next attribute */
		total_attr_len = NLA_ALIGN(attr->nla_len);
		rem -= total_attr_len;
		attr = (struct nlattr *) ((char *) attr + total_attr_len);
	}

	return status;
}

static void client_nl_send_bad_resp(struct nl_msg *nl_req)
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
	ret = sendto(priv.nl_rdma, &resp_msg, datalen, 0,
		     (void *)&dst_addr,
		     (socklen_t)sizeof(dst_addr));
	if (ret != datalen)
		ip2gid_log(IP2GID_LOG_ERR,
			   "Response wasn't sent to kernel in full\n");
}

static int client_ip_recv(union addr_sa *addr,
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
	err = recv(priv.nl_rdma, nl_req, sizeof(*nl_req), 0);
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
		client_nl_send_bad_resp(nl_req);
		goto recv_again;
	}

	if ((nl_req->nlmsg_hdr.nlmsg_len - NLMSG_HDRLEN) <
	    (sizeof(struct rdma_ls_ip_resolve_header) +
	     sizeof(struct nlattr)))
		goto recv_again;

	err = client_nl_rdma_process_ip(nl_req, addr, addr_size,
					req);

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

static void *run_server(void *arg)
{
	struct sockaddr_in addr = {};
	struct ip2gid_obj resp = {};
	struct ip2gid_obj req = {};
	socklen_t addr_len;
	ssize_t n;
	int err;

	addr_len = sizeof(addr);
loop:
	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));
	memset(&addr, 0, sizeof(addr));
	n = recvfrom(priv.sockfd_s_ip4, req.data, sizeof(req.data),
		     MSG_WAITALL, (void *)&addr,
		     &addr_len);

	if (n <= 0) {
		ip2gid_log(IP2GID_LOG_INFO,
			   "recv from socket isn't good (err = %d)\n", n);
		goto loop;
	}

	if (msg_length_check(&req, n)) {
		ip2gid_log(IP2GID_LOG_INFO,
			   "Msg recvied isn't valid\n");
		goto loop;
	}

	req.data_len = n;

	err = server_fill_req(&req, &resp);
	if (err)
		goto loop;

	sendto(priv.sockfd_s_ip4,
	       resp.data, resp.data_len,
	       0,
	       (void *)&addr, addr_len);
	goto loop;

	return NULL;
}

static void client_nl_rdma_send_resp(struct cell_req *orig_req,
				     struct ip2gid_hdr *resp_hdr)
{
	char gid_str[INET6_ADDRSTRLEN] = {};
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


	ip2gid_inet_ntop(IP2GID_LOG_INFO,
			 AF_INET6,
			 gid_resp->gid, gid_str,
			 sizeof(gid_str));
	ip2gid_log(IP2GID_LOG_INFO,
		   "Sending GID resp: %s to kernel (seq = %u)\n",
		   gid_str,
		   orig_req->seq);
	datalen = NLMSG_ALIGN(resp_msg.nlmsg_hdr.nlmsg_len);
	ret = sendto(priv.nl_rdma, &resp_msg, datalen, 0,
		     (void *)&dst_addr,
		     (socklen_t)sizeof(dst_addr));
	if (ret != datalen)
		ip2gid_log(IP2GID_LOG_ERR,
			   "Response wasn't sent to kernel in full\n");
}

static void *run_client_recv(void *arg)
{
	union addr_sa resp_addr = {};
	struct ip2gid_obj resp = {};
	struct ip2gid_hdr *resp_hdr;
	socklen_t resp_addr_size;
	struct cell_req *_pending;
	struct cell_req pending;
	int sockfd;
	int err;

	resp_addr_size = sizeof(resp_addr.sa);
	sockfd = priv.sockfd_c_ip4;
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
	client_nl_rdma_send_resp(&pending, resp_hdr);

	goto loop;

	return NULL;
}

static void *run_client_send(void *arg)
{
	union addr_sa req_addr = {};
	struct ip2gid_obj req = {};
	struct nl_msg nl_req = {};
	struct cell_req *pending;
	socklen_t req_addr_size;
	ssize_t err;
	int sockfd;

	sockfd = priv.sockfd_c_ip4;

loop:
	err = client_ip_recv(&req_addr, &req_addr_size, &req, &nl_req);
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

static void show_usage(char *program)
{
	printf("usage: %s [OPTION]\n", program);
	printf("   [-l, --log=level]  - 0 = All\n");
	printf("                      - 1 = Warn\n");
	printf("                      - 2 = Error\n");
	printf("   [-v, --version]    - show version\n");
	printf("   [-h, --help]       - Show help\n");
}

int main(int argc, char **argv)
{
	static const struct option long_opts[] = {
                {"log", 1, NULL, 'l'},
		{"version", 0, NULL, 'v'},
                {},
        };
	pthread_t tid[3];
	int level;
	int err;
	int op;

	while ((op = getopt_long(argc, argv, "hvl:",
				 long_opts, NULL)) != -1) {
		switch (op) {
		case 'l':
			level = atoi(optarg);
			if (level == 0)
				log_level = IP2GID_LOG_ALL;
			else if (level == 1)
				log_level = IP2GID_LOG_WARN;
			else if (level == 2)
				log_level = IP2GID_LOG_ERR;
			else {
				printf("Not valid log level\n");
				exit(1);
			}

			break;
		case 'v':
			printf("%s %s\n", PROJECT_NAME, PROJECT_VERSION);
			exit(0);
		case 'h':
		default:
			show_usage(argv[0]);
			exit(0);
		}
	}

	flog = ip2gid_open_log();

	err = create_server();
	if (err)
		return err;

	err = create_client();
	if (err)
		return err;

	err = pthread_create(&tid[0], NULL, &run_server, NULL);
	if (err)
		return err;

	err = pthread_create(&tid[1], NULL, &run_client_send, NULL);
	if (err)
		return err;

	err = pthread_create(&tid[1], NULL, &run_client_recv, NULL);
	if (err)
		return err;

	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);
	pthread_join(tid[2], NULL);

	return 0;
}
