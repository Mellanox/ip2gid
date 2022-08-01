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

#include "ib_resolve.h"
#include "log.h"
#include "ipr_client.h"
#include "ipr_server.h"
#include "nl_rdma.h"
#include "path_resolve.h"

#include "config.h"

struct ib_resolve priv;

static int server_port = IP2GID_SERVER_PORT;
static unsigned int log_level = RESOLV_LOG_INFO;

static void show_usage(char *program)
{
	printf("usage: %s [OPTION]\n", program);
	printf("   [-l, --log=level]  - 0 = All\n");
	printf("                      - 1 = Info\n");
	printf("                      - 2 = Warn\n");
	printf("                      - 3 = Error\n");
	printf("   [-v, --version]    - show version\n");
	printf("   [-h, --help]       - Show help\n");
}

static int parse_opt(int argc, char **argv)
{
	static const struct option long_opts[] = {
                {"log", 1, NULL, 'l'},
		{"version", 0, NULL, 'v'},
                {},
        };
	int op;

	while ((op = getopt_long(argc, argv, "hvl:",
				 long_opts, NULL)) != -1) {
		switch (op) {
		case 'l':
			log_level = atoi(optarg);
			if (log_level >= RESOLV_LOG_MAX) {
				printf("Not valid log level %d\n", log_level);
				return -EINVAL;
			}

			break;
		case 'v':
			printf("%s %s\n", PROJECT_NAME, PROJECT_VERSION);
			return -1;
		case 'h':
		default:
			show_usage(argv[0]);
			return -1;
		}
	}

	return 0;
}

static int start_ip2gid_resolve(struct ib_resolve *ibr)
{
	int err;

	ibr->ipr.server_port = server_port;

	err = ipr_server_create(&ibr->ipr);
	if (err)
		return err;

	err = ipr_client_create(&ibr->ipr);
	if (err)
		return err;

	err = pthread_create(&ibr->tid_ipr_server, NULL,
			     &run_ipr_server, &ibr->ipr);
	if (err)
		return err;

	err = pthread_create(&ibr->tid_ipr_client, NULL,
			     &run_ipr_client, &ibr->ipr);
	if (err)
		return err;

	return 0;
}

static int start_path_resolve(struct ib_resolve *ibr)
{
	int err;

	err = path_resolve_init();
	if (err)
		return err;

	err = pthread_create(&ibr->tid_path_resolve, NULL,
			     &run_path_resolve, NULL);
	if (err)
		goto fail;

	return 0;

fail:
	path_resolve_done();
	return err;
}

int main(int argc, char **argv)
{
	int err;

	err = parse_opt(argc, argv);
	if (err)
		return err;

	priv.ipr.server_port = server_port;

	err = resolv_open_log(log_level);
	if (err)
		return err;

	err = start_ip2gid_resolve(&priv);
	if (err)
		return err;

	err = start_path_resolve(&priv);
	if (err)
		return err;

	err = start_nl_rdma(&priv);
	if (err)
		return err;

	pthread_join(priv.tid_ipr_client, NULL);
	pthread_join(priv.tid_ipr_server, NULL);
	pthread_join(priv.tid_path_resolve, NULL);
	pthread_join(priv.tid_nl_rdma, NULL);

	return 0;
}
