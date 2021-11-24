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
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <ifaddrs.h>

#include <getopt.h>
#include <msg_spec.h>

#include "ip2gid.h"
#include "log.h"
#include "client.h"

#include "config.h"

struct nl_ip2gid priv = {-1, -1, -1, 0, NULL};

static int server_port = IP2GID_SERVER_PORT;
static int log_level = IP2GID_LOG_ALL;

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

	err = ip2gid_open_log(log_level);
	if (err)
		return err;

	priv.server_port = server_port;
	err = create_server();
	if (err)
		return err;

	err = create_client(&priv);
	if (err)
		return err;

	err = pthread_create(&tid[0], NULL, &run_server, NULL);
	if (err)
		return err;

	err = pthread_create(&tid[1], NULL, &run_client_send, &priv);
	if (err)
		return err;

	err = pthread_create(&tid[1], NULL, &run_client_recv, &priv);
	if (err)
		return err;

	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);
	pthread_join(tid[2], NULL);

	return 0;
}
