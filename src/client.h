/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */
#ifndef _CLIENT_H
#define _CLIENT_H

#include "ip2gid.h"

int create_client(struct nl_ip2gid *priv);
void *run_client_recv(void *arg);
void *run_client_send(void *arg);

#endif /* CLIENT_H */
