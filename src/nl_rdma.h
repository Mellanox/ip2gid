/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2022 NVIDIA CORPORATION. All rights reserved
 */

#ifndef _NL_RDMA_H
#define _NL_RDMA_H

#include "ib_resolve.h"

int start_nl_rdma(struct ib_resolve *priv);

int nl_rdma_send_resp(struct nl_msg *msg);
#endif	/* _NL_RDMA_H */
