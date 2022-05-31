/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2021 NVIDIA CORPORATION. All rights reserved
 */

#include "ip2gid.h"
#include "log.h"

int msg_length_check(struct ip2gid_obj *obj, uint32_t max_len)
{
	struct ip2gid_tlv_hdr *tlv;
	struct ip2gid_hdr *hdr;
	uint16_t num_tlvs;

	if (max_len <= sizeof(struct ip2gid_hdr)) {
		ip2gid_log_info("Msg length too short\n");
		return -1;
	}

	hdr = (struct ip2gid_hdr *)obj->data;
	ip2gid_log_info("Checking new Msg (msg_id = %u)\n",
			ntohl(hdr->msg_id));
	num_tlvs = ntohs(hdr->num_tlvs);
	if (!num_tlvs) {
		ip2gid_log_info("\tNo TLVS in Msg\n");
		return -1;
	}

	ip2gid_log_info("\tNum tlvs:%u\n", num_tlvs);
	if (hdr->version > IP2GID_CURRENT_VERSION) {
		ip2gid_log_info("\tMsg version isn't supported\n");
		return -1;
	}

	max_len -= sizeof(struct ip2gid_hdr);

	tlv = (struct ip2gid_tlv_hdr *)hdr->tlvs;
	while (num_tlvs && max_len >= 0) {
		uint16_t tlv_len = ntohs(tlv->len);

		max_len -= tlv_len;
		switch (ntohs(tlv->type)) {
		case IP2GID_REQ_NONE:
			if (tlv_len != sizeof(struct ip2gid_tlv_hdr)) {
				ip2gid_log_info("\tTLV: None: invalid length (len= %u)\n",
						tlv_len);
				return -1;
			}
			break;
		case IP2GID_REQ_IPV4:
			if (tlv_len != sizeof(struct ip2gid_req_ipv4)) {
				ip2gid_log_info("\tTLV: IPV4: invalid length (len = %u)\n",
						tlv_len);
				return -1;
			}
			break;
		case IP2GID_RESP_GID:
			if (tlv_len != sizeof(struct ip2gid_resp_gid)) {
				ip2gid_log_info("\tTLV: GID: invalid length (len = %u)\n",
						tlv_len);
				return -1;
			}
			break;
		default:
			ip2gid_log_info("\tTLV: Unknown type\n");
			return -1;
		}
		tlv = (struct ip2gid_tlv_hdr *)((char *)tlv + tlv_len);
		num_tlvs--;
	}
	if (num_tlvs == 0 && max_len >= 0) {
		ip2gid_log_info("\tMsg passed basic checks\n");
		return 0;
	}

	return -1;
}
