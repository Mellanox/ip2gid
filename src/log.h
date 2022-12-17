/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */
#ifndef _LOG_H
#define _LOG_H

#include <arpa/inet.h>
#include <stdio.h>

#define RESOLV_LOG_FILE "stdout"

#define resolv_log(level, format, ...) \
	resolv_write(level, "%s: "format, __func__, ## __VA_ARGS__)

enum {
	RESOLV_LOG_ALL,
	RESOLV_LOG_DBG = RESOLV_LOG_ALL,
	RESOLV_LOG_INFO,
	RESOLV_LOG_WARN,
	RESOLV_LOG_ERR,
	RESOLV_LOG_MAX,
};

#define ip2gid_log_dbg(format, ...) \
	resolv_write(RESOLV_LOG_DBG, " <IPR> %s: "format, __func__, ## __VA_ARGS__)

#define ip2gid_log_info(format, ...) \
	resolv_write(RESOLV_LOG_INFO, " <IPR> %s: "format, __func__, ## __VA_ARGS__)

#define ip2gid_log_warn(format, ...) \
	resolv_write(RESOLV_LOG_WARN, " <IPR> %s: "format, __func__, ## __VA_ARGS__)

#define ip2gid_log_err(format, ...) \
	resolv_write(RESOLV_LOG_ERR, " <IPR> %s: "format, __func__, ## __VA_ARGS__)

#define nl_log_dbg(format, ...) \
	resolv_write(RESOLV_LOG_DBG, " %s: "format, __func__, ## __VA_ARGS__)

#define nl_log_info(format, ...) \
	resolv_write(RESOLV_LOG_INFO, " %s: "format, __func__, ## __VA_ARGS__)

#define nl_log_warn(format, ...) \
	resolv_write(RESOLV_LOG_WARN, " %s: "format, __func__, ## __VA_ARGS__)

#define nl_log_err(format, ...) \
	resolv_write(RESOLV_LOG_ERR, " %s: "format, __func__, ## __VA_ARGS__)

#define path_dbg(format, ...) \
	resolv_write(RESOLV_LOG_DBG, " <PR> %s: "format, __func__, ## __VA_ARGS__)

#define path_info(format, ...) \
	resolv_write(RESOLV_LOG_INFO, " <PR> %s: "format, __func__, ## __VA_ARGS__)

#define path_warn(format, ...) \
	resolv_write(RESOLV_LOG_WARN, " <PR> %s: "format, __func__, ## __VA_ARGS__)

#define path_err(format, ...) \
	resolv_write(RESOLV_LOG_ERR, " <PR> %s: "format, __func__, ## __VA_ARGS__)

void resolv_write(int level, const char *format, ...);
int resolv_open_log(int log_level);
void resolv_inet_ntop(int level, int af,
		      const void *src, char *dst, socklen_t size);

#endif	/* _LOG_H */
