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
static int log_level = IP2GID_LOG_ALL;

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

	err = pthread_create(&tid[1], NULL, &run_client_recv, &priv);
	if (err)
		return err;

	pthread_join(tid[0], NULL);
	pthread_join(tid[1], NULL);
	pthread_join(tid[2], NULL);

	return 0;
}
