/* SPDX-License-Identifier: ((GPL-2.0 WITH Linux-syscall-note) OR BSD-2-Clause) */
/*
 * Copyright (c) 2022 NVIDIA CORPORATION. All rights reserved
 */

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>

#include <infiniband/umad.h>
#include <infiniband/umad_sa.h>
#include <infiniband/umad_types.h>
#include <rdma/ib_user_sa.h>

#include "ib_resolve.h"
#include "log.h"
#include "nl_rdma.h"
#include "path_resolve.h"

struct pr_umad_port {
	umad_port_t umad_port;
	int portid;
	int agentid;
};

#define MAX_UMAD_PORTS 16
static struct pr_umad_port uports[MAX_UMAD_PORTS];
static unsigned int umad_port_num;

#define PR_TIMEOUT 2000		/* ms */
struct pr_req {
	bool in_use;
	uint32_t nltype;
	uint32_t nlseq;

	uint8_t path_use;
	__be64 comp_mask;
	uint64_t tid;		/* Transaction ID */
};

struct path_req_ctl {
	struct pr_req reqs[DEFAULT_PENDING_REQUESTS];
	pthread_mutex_t lock;
	int outstanding_req_num;
	uint64_t next_tid;
};
static struct path_req_ctl ctl;

static int req_slot_alloc(void)
{
	int i;

	pthread_mutex_lock(&ctl.lock);
	for (i = 0; i < DEFAULT_PENDING_REQUESTS; i++)
		if (!ctl.reqs[i].in_use)
			break;

	if (i == DEFAULT_PENDING_REQUESTS) {
		path_err("Failed to found an available req block\n");
		i = -1;
		goto out;
	}

	ctl.reqs[i].in_use = true;
	ctl.reqs[i].tid = ctl.next_tid;

	ctl.next_tid++;
	ctl.outstanding_req_num++;
out:
	pthread_mutex_unlock(&ctl.lock);
	return i;
}

static void __req_slot_release(struct pr_req *req)
{
	memset(req, 0, sizeof(*req));
	ctl.outstanding_req_num--;
}

static void req_slot_release(struct pr_req *req)
{
	pthread_mutex_lock(&ctl.lock);
	__req_slot_release(req);
	pthread_mutex_unlock(&ctl.lock);
}

static int __req_slot_find(uint64_t tid)
{
	int i, compared = 0;

	for (i = 0; i < DEFAULT_PENDING_REQUESTS; i++) {
		if (!ctl.reqs[i].in_use)
			continue;

		/* The upper 32-bit of the tid is agent->hi_tid */
		if ((ctl.reqs[i].tid & 0xffffffff) == (tid & 0xffffffff))
			break;

		compared++;
		if (compared == ctl.outstanding_req_num)
			return -1;
	}

	if (i >= DEFAULT_PENDING_REQUESTS)
		return -1;

	return i;
}

static int path_resolve_init_one(const char *ibname, int port)
{
	struct pr_umad_port *uport;
	int err;

	if (umad_port_num >= MAX_UMAD_PORTS)
		return -ENOMEM;

	uport = uports + umad_port_num;

	err = umad_get_port(ibname, port, &uport->umad_port);
	if (err) {
		path_err("umad_get_port(%s, %d) failed %d\n",
			     ibname, port, err);
		return err;
	}

	uport->portid = umad_open_port(uport->umad_port.ca_name,
				       uport->umad_port.portnum);
	if (uport->portid < 0) {
		path_err("umad_open_port failed: %s/%d, err %d\n",
			 ibname, port, errno);
		err = errno;
		goto fail_open_port;
	}

	uport->agentid = umad_register(uport->portid, UMAD_CLASS_SUBN_ADM,
				       UMAD_SA_CLASS_VERSION, 0, NULL);
	if (uport->agentid < 0) {
		path_err("umad_register failed: %s/%d, err %d\n",
			 ibname, port, errno);
		err = errno;
		goto fail_register;
	}

	umad_port_num++;
	return 0;

fail_register:
	umad_close_port(uport->portid);
fail_open_port:
	umad_release_port(&uport->umad_port);

	return err;
}

int path_resolve_init(void)
{
	struct ibv_port_attr port_attr;
	struct ibv_device **dev_list;
	struct ibv_device_attr attr;
	struct ibv_context *ibctx;
	const char *devname;
	int i, j, err, devnum;

	err = umad_init();
	if (err)
		return err;

	dev_list = ibv_get_device_list(&devnum);
	if (!dev_list) {
		path_err("Unable to get ib device list: %d\n", errno);
		return errno;
	}

	for (i = 0; i < devnum; i++) {
		devname = ibv_get_device_name(dev_list[i]);
		if (!devname) {
			path_warn("Dev %d/%d: failed to get name: %d\n", i, devnum, errno);
			continue;
		}
		ibctx = ibv_open_device(dev_list[i]);
		if (!ibctx) {
			path_warn("Dev %s: failed to open: %d\n", devname, errno);
			continue;
		}

		err = ibv_query_device(ibctx, &attr);
		if (err) {
			path_warn("Dev %s: failed to query: %d\n", devname, errno);
			continue;
		}

		for (j = 0; j < attr.phys_port_cnt; j++) {
			err = ibv_query_port(ibctx, j + 1, &port_attr);
			if (err) {
				path_warn("%s/%d: failed to query port: %d\n",
					  devname, j + 1, errno);
				continue;
			}
			if (port_attr.link_layer == IBV_LINK_LAYER_INFINIBAND) {
				path_info("Found an IB port(%d/%d): %s/%d...\n",
					  i, devnum, devname, j + 1);
				err = path_resolve_init_one(devname, j + 1);
				if (err)
					continue;

				path_info("Path resolve init succeeded: %s/%d\n", devname, j + 1);
			}
		}

		ibv_close_device(ibctx);
	}

	ibv_free_device_list(dev_list);

	if (umad_port_num == 0) {
		umad_done();
		return err;
	}

	ctl.next_tid = 0x11220000;
	pthread_mutex_init(&ctl.lock, NULL);
	return 0;
}

void path_resolve_done(void)
{
	int i;

	for (i = 0; i < umad_port_num; i++) {
		umad_unregister(uports[i].portid, uports[i].agentid);
		umad_close_port(uports[i].portid);
		umad_release_port(&uports[i].umad_port);
	}

	umad_port_num = 0;
	umad_done();
}

#define IBV_PATH_RECORD_QOS_MASK 0xfff0
static int do_parse_attr(struct nlattr *attr,
			 struct ibv_path_record *path, __be64 *cmask)
{
	struct rdma_nla_ls_gid *gid;
	uint16_t *pkey, *qos, val;
	uint64_t *sid;
	uint8_t *tcl;
	int err = 0;

	switch (attr->nla_type & RDMA_NLA_TYPE_MASK) {
	case LS_NLA_TYPE_SERVICE_ID:
		sid = (uint64_t *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(*sid))
			path->service_id = htobe64(*sid);
		else
			err = -1;

		*cmask |= IB_COMP_MASK_PR_SERVICE_ID;
		break;

	case LS_NLA_TYPE_DGID:
		gid = (struct rdma_nla_ls_gid *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(gid->gid))
			memcpy(path->dgid.raw, gid->gid, sizeof(path->dgid));
		else
			err = -1;

		*cmask |= IB_COMP_MASK_PR_DGID;
		break;

	case LS_NLA_TYPE_SGID:
		gid = (struct rdma_nla_ls_gid *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(gid->gid))
			memcpy(path->sgid.raw, gid->gid, sizeof(path->sgid));
		else
			err = -1;

		*cmask |= IB_COMP_MASK_PR_SGID;
		break;

	case LS_NLA_TYPE_TCLASS:
		tcl = (uint8_t *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(*tcl))
			path->tclass = *tcl;
		else
			err = -1;

		*cmask |= IB_COMP_MASK_PR_TCLASS;
		break;

	case LS_NLA_TYPE_PKEY:
		pkey = (uint16_t *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(*pkey))
			path->pkey = htobe16(*pkey);
		else
			err = -1;

		*cmask |= IB_COMP_MASK_PR_PKEY;
		break;

	case LS_NLA_TYPE_QOS_CLASS:
		qos = (uint16_t *) NLA_DATA(attr);
		if (NLA_LEN(attr) == sizeof(*qos)) {
			val = be16toh(path->qosclass_sl);
			val &= ~IBV_PATH_RECORD_QOS_MASK;
			val |= (*qos & IBV_PATH_RECORD_QOS_MASK);
			path->qosclass_sl = htobe16(val);
		} else {
			err = -1;
		}

		*cmask |= IB_COMP_MASK_PR_QOS_CLASS;
		break;

	default:
		path_warn("Unknown%s attr %x\n",
			  attr->nla_type & RDMA_NLA_F_MANDATORY ? " mandatory" : "",
			  attr->nla_type);
		if (attr->nla_type & RDMA_NLA_F_MANDATORY)
			return -1;
		break;
	}

	if (err)
		path_err("Invalid attr type %d length %d\n",
			 attr->nla_type & RDMA_NLA_TYPE_MASK, NLA_LEN(attr));

	return err;
}

static int req_nlmsg_resolve_path(const struct nl_msg *msg,
				  struct ibv_path_record *path, __be64 *cmask)
{
	int rheaderlen = NLMSG_ALIGN(sizeof(msg->rheader)), rem, err, alen;
	char sgid[64] = {}, dgid[64] = {};
	struct nlattr *attr;

	*cmask = 0;
	rem = msg->nlmsg_hdr.nlmsg_len - NLMSG_HDRLEN - rheaderlen;
	attr = (struct nlattr *)(msg->data + rheaderlen);
	while (1) {
		if (rem < (int)sizeof(*attr) ||
		    attr->nla_len < sizeof(*attr) ||
		    attr->nla_len > rem)
			break;
		err = do_parse_attr(attr, path, cmask);
		if (err)
			return err;

		alen = NLA_ALIGN(attr->nla_len);
		rem -= alen;
		attr = (struct nlattr *)((unsigned char *)attr + alen);
	}

	path->reversible_numpath = IBV_PATH_RECORD_REVERSIBLE | 1;
	*cmask |= (IB_COMP_MASK_PR_REVERSIBLE | IB_COMP_MASK_PR_NUM_PATH);

	inet_ntop(AF_INET6, path->dgid.raw, dgid, sizeof(dgid));
	inet_ntop(AF_INET6, path->sgid.raw, sgid, sizeof(sgid));
	path_info("Request PR: %s/%d: path_use %d, service_id 0x%llx "
		  "dgid %s sgid %s tclass 0x%x pkey 0x%x qosclass_sl 0x%x, cmask 0x%llx\n",
		  msg->rheader.device_name, msg->rheader.port_num, msg->rheader.path_use,
		  be64toh(path->service_id), dgid, sgid, path->tclass, be16toh(path->pkey),
		  be16toh(path->qosclass_sl), be64toh(*cmask));
	return 0;
}

static void build_mad_getPR(const struct ibv_path_record *pr,
			   uint64_t tid, __be64 comp_mask,
			   struct umad_sa_packet *sa)
{
	sa->mad_hdr.base_version = UMAD_BASE_VERSION;
	sa->mad_hdr.mgmt_class = UMAD_CLASS_SUBN_ADM;
	sa->mad_hdr.class_version = UMAD_SA_CLASS_VERSION;
	sa->mad_hdr.method = UMAD_METHOD_GET;
	sa->mad_hdr.tid = htobe64(tid);
	sa->mad_hdr.attr_id = htobe16(UMAD_SA_ATTR_PATH_REC);
	sa->comp_mask = comp_mask;

	memcpy(sa->data, pr, sizeof(*pr));
}

struct pr_umad_port *find_uport(const char *devname, int port_num)
{
	int i;

	for (i = 0; i < umad_port_num; i++) {
		if (strncmp(uports[i].umad_port.ca_name,
			   devname, strlen(devname)) == 0 &&
			uports[i].umad_port.portnum == port_num)
			return uports + i;
	}
	return NULL;
}

int path_resolve_req(const struct nl_msg *msg)
{
	int reqid, err, len = sizeof(struct umad_hdr) + UMAD_LEN_DATA;
	struct ibv_path_record pr = {};
	struct pr_umad_port *uport;
	struct umad_sa_packet *sa;
	struct pr_req *req;
	uint8_t *umad;

	uport = find_uport((const char *)msg->rheader.device_name,
			   msg->rheader.port_num);
	if (!uport) {
		path_err("Failed to find uport for %s/%d\n",
			 msg->rheader.device_name, msg->rheader.port_num);
		return -ENOENT;
	}

	umad = calloc(1, len + umad_size());
	if (!umad) {
		path_err("calloc %d failed %d\n", len + umad_size(), errno);
		return errno;
	}

	reqid = req_slot_alloc();
	if (reqid < 0) {
		err = EBUSY;
		goto fail_req_slot;
	}

	req = ctl.reqs + reqid;
	req->nlseq = msg->nlmsg_hdr.nlmsg_seq;
	req->nltype = msg->nlmsg_hdr.nlmsg_type;
	req->path_use = msg->rheader.path_use;
	path_info("Get req from %s/%d: slot %d, tid 0x%llx, nlseq 0x%x, path_use %d\n",
		  msg->rheader.device_name, msg->rheader.port_num, reqid, req->tid,
		  req->nlseq, req->nltype, msg->rheader.path_use);

	umad_set_addr(umad, uport->umad_port.sm_lid, 1,
		      uport->umad_port.sm_sl, UMAD_QKEY);

	err = req_nlmsg_resolve_path(msg, &pr, &req->comp_mask);
	if (err)
		goto fail_resolve_path;

	sa = umad_get_mad(umad);
	build_mad_getPR(&pr, req->tid, req->comp_mask, sa);
	err = umad_send(uport->portid, uport->agentid, umad, len, PR_TIMEOUT, 0);
	if (err)
		path_err("umad_send failed %d\n", err);

	free(umad);
	return err;

fail_resolve_path:
	req_slot_release(req);
fail_req_slot:
	free(umad);
	return err;
}

static __u32 get_rec_flags(uint8_t path_use)
{
	if (path_use == LS_RESOLVE_PATH_USE_UNIDIRECTIONAL)
		return IB_PATH_PRIMARY | IB_PATH_OUTBOUND;
	else
		return IB_PATH_PRIMARY | IB_PATH_GMP | IB_PATH_BIDIRECTIONAL;
}

struct nl_pr {
	struct nlattr attr;
	struct ib_path_rec_data rec;
};

static int send_resp(struct ib_user_mad *umad,
		     struct umad_sa_packet *sa,
		     uint32_t type, uint32_t seq, uint8_t path_use)
{
	struct nl_msg resp = {};
	struct nl_pr *pr = (struct nl_pr *)resp.data;
	int datalen, ret;

	pr->attr.nla_type = LS_NLA_TYPE_PATH_RECORD;
	pr->attr.nla_len = sizeof(*pr);
	pr->rec.flags = get_rec_flags(path_use);
	memcpy(pr->rec.path_rec, sa->data, sizeof(*pr));

	resp.nlmsg_hdr.nlmsg_len = NLMSG_HDRLEN + pr->attr.nla_len;
        resp.nlmsg_hdr.nlmsg_pid = getpid();
	resp.nlmsg_hdr.nlmsg_type = type;
	resp.nlmsg_hdr.nlmsg_seq = seq;

	datalen = NLMSG_ALIGN(resp.nlmsg_hdr.nlmsg_len);
	ret = nl_rdma_send_resp(&resp);
	if (ret != datalen) {
		path_err("sendto failed %d errno %d\n", ret, errno);
		return ret;
	}

	return 0;
}

static int handle_mad_GetResp_PR(struct ib_user_mad *umad,
				 struct umad_sa_packet *sa)
{
	uint32_t nltype, nlseq;
	uint8_t path_use;
	int req_id;

	pthread_mutex_lock(&ctl.lock);
	req_id = __req_slot_find(be64toh(sa->mad_hdr.tid));
	if (req_id < 0) {
		path_warn("Unknown resp tid 0x%llx, discarded\n",
			  be64toh(sa->mad_hdr.tid));
		pthread_mutex_unlock(&ctl.lock);
		return 0;
	}

	nltype = ctl.reqs[req_id].nltype;
	nlseq = ctl.reqs[req_id].nlseq;
	path_use = ctl.reqs[req_id].path_use;

	__req_slot_release(&ctl.reqs[req_id]);
	pthread_mutex_unlock(&ctl.lock);

	return send_resp(umad, sa, nltype, nlseq, path_use);
}

static int recv_one_mad(int uport_id)
{
	char resp[sizeof(struct ib_user_mad) + sizeof(struct umad_sa_packet)];
	struct ib_user_mad *umad = (struct ib_user_mad *)resp;
	struct umad_sa_packet *sa = (struct umad_sa_packet*)(umad + 1);
	int len = sizeof(struct umad_hdr) + UMAD_LEN_DATA, err;
	struct pr_umad_port *uport = &uports[uport_id];

	err = umad_recv(uport->portid, umad, &len, -1);
	if (err < 0) {
		path_err("recv failed %d, errno %d\n", err, errno);
		return err;
	}

	path_info("mad received len %d: agent_id 0x%x, status 0x%x, timeout_ms 0x%x, length 0x%x,"
		  "sa method 0x%x status 0x%x attr_id 0x%x, tid 0x%llx\n",
		  len, umad->agent_id, umad->status, umad->timeout_ms, umad->length,
		  sa->mad_hdr.method, sa->mad_hdr.status, be16toh(sa->mad_hdr.attr_id),
		  be64toh(sa->mad_hdr.tid));

	if (umad->status || sa->mad_hdr.status) {
		path_err("umad failed: umad status 0x%x, sa status 0x%x\n",
			 umad->status, sa->mad_hdr.status);
		return umad->status | sa->mad_hdr.status;
	}

	if ((sa->mad_hdr.method != UMAD_METHOD_GET_RESP) ||
	    (be16toh(sa->mad_hdr.attr_id) != UMAD_SA_ATTR_PATH_REC))
		return 0;

	return handle_mad_GetResp_PR(umad, sa);
}

static int set_fd_block(int fd)
{
	int v;

	v = fcntl(fd, F_GETFL);
	if (v < 0)
		return v;

	v &= ~(unsigned int)O_NONBLOCK;
	if (fcntl(fd, F_SETFL, v) < 0)
		return -1;

	return 0;
}

void *run_path_resolve(void *arg)
{
	struct pollfd *fds;
	int i, err;

	if (!umad_port_num) {
		path_err("path resolve not initialized\n");
		return NULL;
	}

	fds = calloc(umad_port_num, sizeof(*fds));
	if (!fds) {
		path_err("calloc %d/%ld failed: %d\n",
			 umad_port_num, sizeof(*fds), errno);
		return NULL;
	}

	for (i = 0; i < umad_port_num; i ++) {
		fds[i].fd = umad_get_fd(uports[i].portid);
		fds[i].events = POLLIN;
		err = set_fd_block(fds[i].fd);
		if (err)
			path_warn("%s/%d: umad fd %d is blocking\n",
				  uports[i].umad_port.ca_name,
				  uports[i].umad_port.portnum,
				  fds[i].fd);
	}

	do {
		err = poll(fds, umad_port_num, -1);
		if (err < 0) {
			path_err("poll error %d\n", errno);
			continue;
		}

		for (i = 0; i < umad_port_num; i++) {
			if (!fds[i].revents)
				continue;

			if (fds[i].revents & POLLIN)
				recv_one_mad(i);

			fds[i].revents = 0;
		}

	} while (1);

	return NULL;
}
