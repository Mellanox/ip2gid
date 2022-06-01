/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */
#ifndef _SERVER_H
#define _SERVER_H

#include "ip2gid.h"

int ipr_server_create(struct nl_ip2gid *priv);

void *run_ipr_server(void *arg);

#endif /* SERVER_H */
