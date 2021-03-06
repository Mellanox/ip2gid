/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */
#ifndef _LOG_H
#define _LOG_H

#include <arpa/inet.h>
#include <stdio.h>

#define IP2GID_LOG_FILE "stdout"

#define ip2gid_log(level, format, ...) \
	ip2gid_write(level, "%s: "format, __func__, ## __VA_ARGS__)

enum {
	IP2GID_LOG_ALL,
	IP2GID_LOG_INFO,
	IP2GID_LOG_WARN,
	IP2GID_LOG_ERR,
};

void ip2gid_write(int level, const char *format, ...);
int ip2gid_open_log(int log_level);
void ip2gid_inet_ntop(int level, int af,
		      const void *src, char *dst, socklen_t size);

#endif	/* _LOG_H */
