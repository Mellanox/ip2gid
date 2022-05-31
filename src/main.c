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
#include "server.h"

#include "config.h"

struct nl_ip2gid priv = {-1, -1, -1, 0, NULL};

static int server_port = IP2GID_SERVER_PORT;
static unsigned int log_level = RESOLV_LOG_ALL;

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

int main(int argc, char **argv)
{
	pthread_t tid[3];
	int err;

	err = parse_opt(argc, argv);
	if (err)
		return err;

	err = resolv_open_log(log_level);
	if (err)
		return err;

	priv.server_port = server_port;
	err = create_server(&priv);
	if (err)
		return err;

	err = create_client(&priv);
	if (err)
		return err;

	err = pthread_create(&tid[0], NULL, &run_server, &priv);
	if (err)
		return err;

	err = pthread_create(&tid[1], NULL, &run_client_send, &priv);
	if (err)
		return err;

	err = pthread_create(&tid[2], NULL, &run_client_recv, &priv);
	if (err)
		return err;

	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);
	pthread_join(tid[2], NULL);

	return 0;
}
