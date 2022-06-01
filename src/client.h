/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */
#ifndef _CLIENT_H
#define _CLIENT_H

#include "ip2gid.h"

int ipr_client_create(struct nl_ip2gid *priv);
void *run_ipr_client(void *arg);

int ipr_resolve_req(const struct nl_ip2gid *ipr, const struct nl_msg *nl_req);
#endif /* CLIENT_H */
