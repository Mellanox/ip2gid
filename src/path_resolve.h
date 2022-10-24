/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2022 NVIDIA CORPORATION. All rights reserved
 */

#ifndef _PATH_RESOLVE_H
#define _PATH_RESOLVE_H

#define IB_COMP_MASK_PR_SERVICE_ID         (htobe64(1 << 0) | \
					    htobe64(1 << 1))
#define IB_COMP_MASK_PR_DGID                htobe64(1 << 2)
#define IB_COMP_MASK_PR_SGID                htobe64(1 << 3)
#define IB_COMP_MASK_PR_DLID                htobe64(1 << 4)
#define IB_COMP_MASK_PR_SLID                htobe64(1 << 5)
#define IB_COMP_MASK_PR_RAW_TRAFFIC         htobe64(1 << 6)
/* RESERVED                                 htobe64(1 << 7) */
#define IB_COMP_MASK_PR_FLOW_LABEL          htobe64(1 << 8)
#define IB_COMP_MASK_PR_HOP_LIMIT           htobe64(1 << 9)
#define IB_COMP_MASK_PR_TCLASS              htobe64(1 << 10)
#define IB_COMP_MASK_PR_REVERSIBLE          htobe64(1 << 11)
#define IB_COMP_MASK_PR_NUM_PATH            htobe64(1 << 12)
#define IB_COMP_MASK_PR_PKEY                htobe64(1 << 13)
#define IB_COMP_MASK_PR_QOS_CLASS           htobe64(1 << 14)
#define IB_COMP_MASK_PR_SL                  htobe64(1 << 15)
#define IB_COMP_MASK_PR_MTU_SELECTOR        htobe64(1 << 16)
#define IB_COMP_MASK_PR_MTU                 htobe64(1 << 17)
#define IB_COMP_MASK_PR_RATE_SELECTOR       htobe64(1 << 18)
#define IB_COMP_MASK_PR_RATE                htobe64(1 << 19)
#define IB_COMP_MASK_PR_PACKET_LIFETIME_SELECTOR htobe64(1 << 20)
#define IB_COMP_MASK_PR_PACKET_LIFETIME     htobe64(1 << 21)
#define IB_COMP_MASK_PR_PREFERENCE          htobe64(1 << 22)
/* RESERVED                                 htobe64(1 << 23) */

int path_resolve_init(void);
void path_resolve_done(void);

void *run_path_resolve(void *arg);

int path_resolve_req(const struct nl_msg *msg);
#endif /* _PATH_RESOLVE_H */

