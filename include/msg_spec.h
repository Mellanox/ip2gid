/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2020 NVIDIA CORPORATION. All rights reserved
 */

#include <linux/types.h>

#ifndef MSG_SPEC_H
#define MSG_SPEC_H

#define IP2GID_CURRENT_VERSION 0x1

enum ip2gid_tlvs {
	IP2GID_REQ_NONE = 0,
	IP2GID_REQ_IPV4 = 1,
	IP2GID_RESP_GID = 0x10,
};

struct ip2gid_hdr {
	__u8 version;
	__u8 resv0[3];
	__be32 msg_id;
	__be16 num_tlvs;
	__u8 resv1[2];
	__u8 tlvs[];
} __attribute__((packed));

struct ip2gid_tlv_hdr {
	__be16 type;
	__be16 len;
} __attribute__((packed));

struct ip2gid_req_ipv4 {
	struct ip2gid_tlv_hdr hdr;
	__be32 ipv4;
} __attribute__((packed));

struct ip2gid_resp_gid {
	struct ip2gid_tlv_hdr hdr;
	__u8 gid[16];
} __attribute__((packed));

#endif
