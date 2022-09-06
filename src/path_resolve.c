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
	char ca_name[UMAD_CA_NAME_LEN];
	int portnum;

	unsigned int sm_lid;
	unsigned int sm_sl;

	int portid;		/* umad port id */
	int agentid;
};


#define MAX_UMAD_PORTS 32
static struct pr_umad_port uports[MAX_UMAD_PORTS];
static unsigned int umad_port_num;

struct arr_port {
	struct pr_umad_port *uport;
	uint8_t link_layer;

	bool activated;
};

#define MAX_PORTS_PER_DEVICE 4
struct arr_device {
	const char *name;
	struct ibv_device *ibdev;
	struct ibv_context *ibctx;
	unsigned int port_cnt;
	struct arr_port ports[MAX_PORTS_PER_DEVICE];
};

static struct ibv_device **ibdev_list;
static struct arr_device *arrdevs;
static int ibdev_num;

#define PR_TIMEOUT 2000		/* ms */
struct pr_req {
	bool in_use;
	uint32_t nltype;
	uint32_t nlseq;

	uint8_t path_use;
	__be64 comp_mask;
	uint64_t tid;		/* Transaction ID */

	struct timespec stamp;
};

#define PENDING_REQ_THRESHHOLD  (DEFAULT_PENDING_REQUESTS / 3)
#define PR_PENDING_TIMEOUT 60		/* seconds */
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

	clock_gettime(CLOCK_REALTIME, &ctl.reqs[i].stamp);
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

static void path_resolve_clean_one(struct arr_port *arrport)
{
	struct pr_umad_port *uport = arrport->uport;

	path_dbg("%s/%d: umad clean\n",
		 uport->ca_name, uport->portnum);

	umad_unregister(uport->portid, uport->agentid);
	umad_close_port(uport->portid);
	arrport->activated = false;
}

static int path_resolve_init_one(struct arr_port *arrport)
{
	struct pr_umad_port *uport = arrport->uport;
	int err;

	uport->portid = umad_open_port(uport->ca_name, uport->portnum);
	if (uport->portid < 0) {
		path_err("umad_open_port failed: %s/%d, err %d\n",
			 uport->ca_name, uport->portnum, errno);
		return errno;
	}

	uport->agentid = umad_register(uport->portid, UMAD_CLASS_SUBN_ADM,
				       UMAD_SA_CLASS_VERSION, 0, NULL);
	if (uport->agentid < 0) {
		path_err("umad_register failed: %s/%d, err %d\n",
			 uport->ca_name, uport->portnum, errno);
		err = errno;
		goto fail_register;
	}

	arrport->activated = true;
	path_dbg("%s/%d: umad init succeeded\n", uport->ca_name, uport->portnum);

	return 0;

fail_register:
	umad_close_port(uport->portid);
	return err;
}

int path_resolve_init(void)
{
	struct ibv_port_attr port_attr;
	struct ibv_device_attr attr;
	struct ibv_context *ibctx;
	const char *devname;
	int i, j, err;

	err = umad_init();
	if (err)
		return err;

	ibdev_list = ibv_get_device_list(&ibdev_num);
	if (!ibdev_list) {
		path_err("Unable to get ib device list: %d\n", errno);
		return errno;
	}

	arrdevs = calloc(ibdev_num, sizeof(*arrdevs));
	if (!arrdevs) {
		path_err("calloc ibdev_ibctx_list %d failed\n", ibdev_num);
		ibv_free_device_list(ibdev_list);
	}

	for (i = 0; i < ibdev_num; i++) {
		devname = ibv_get_device_name(ibdev_list[i]);
		if (!devname) {
			path_warn("Dev %d/%d: failed to get name: %d\n",
				  i, ibdev_num, errno);
			continue;
		}
		ibctx = ibv_open_device(ibdev_list[i]);
		if (!ibctx) {
			path_warn("Dev %s: failed to open: %d\n", devname, errno);
			continue;
		}

		err = ibv_query_device(ibctx, &attr);
		if (err) {
			path_warn("Dev %s: failed to query: %d\n", devname, errno);
			continue;
		}

		if (attr.phys_port_cnt > MAX_PORTS_PER_DEVICE) {
			path_err("Dev %s: unsupported phys_port_cnt %d\n",
				 devname, attr.phys_port_cnt);
			continue;
		}
		for (j = 0; j < attr.phys_port_cnt; j++) {
			err = ibv_query_port(ibctx, j + 1, &port_attr);
			if (err) {
				path_warn("%s/%d: ibv_query_port failed: %d\n",
					  devname, j + 1, errno);
				continue;
			}

			strncpy(uports[umad_port_num].ca_name, devname,
				strlen(devname));
			uports[umad_port_num].portnum = j + 1;

			arrdevs[i].ports[j].uport = &uports[umad_port_num];
			arrdevs[i].ports[j].link_layer = port_attr.link_layer;
			if (port_attr.link_layer == IBV_LINK_LAYER_INFINIBAND) {
				path_info("Found an IB port(%d/%d): %s/%d, sm_lid %d, sm_sl %d\n",
					  i, ibdev_num, devname, j + 1,
					  port_attr.sm_lid, port_attr.sm_sl);

				uports[umad_port_num].sm_lid = port_attr.sm_lid;
				uports[umad_port_num].sm_sl = port_attr.sm_sl;
				err = path_resolve_init_one(&arrdevs[i].ports[j]);
				if (err)
					continue;
			}

			umad_port_num++;
		}

		arrdevs[i].name = devname;
		arrdevs[i].ibctx = ibctx;
		arrdevs[i].port_cnt = attr.phys_port_cnt;
	}

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

	for (i = 0; i < ibdev_num; i++)
		ibv_close_device(arrdevs[i].ibctx);

	ibv_free_device_list(ibdev_list);
	ibdev_list = NULL;
	ibdev_num = 0;
	free(arrdevs);
	arrdevs = NULL;

	for (i = 0; i < umad_port_num; i++) {
		umad_unregister(uports[i].portid, uports[i].agentid);
		umad_close_port(uports[i].portid);
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
	path_dbg("Request PR: %s/%d: path_use %d, service_id 0x%llx "
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
		if (strncmp(uports[i].ca_name,
			   devname, strlen(devname)) == 0 &&
			uports[i].portnum == port_num)
			return uports + i;
	}
	return NULL;
}

#define PR_PENDING_CLEAR_NUM 10	/* How many slots to clear in each time */
static void clear_timeout_req(void)
{
	struct timespec now;
	int i, cleared = 0;

	pthread_mutex_lock(&ctl.lock);
	if (ctl.outstanding_req_num < PENDING_REQ_THRESHHOLD)
		goto out;

	clock_gettime(CLOCK_REALTIME, &now);
	for (i = 0; i < DEFAULT_PENDING_REQUESTS; i++) {
		if (!ctl.reqs[i].in_use ||
		    (now.tv_sec - ctl.reqs[i].stamp.tv_sec) <
		    PR_PENDING_TIMEOUT)
			continue;

		path_warn("Clear timeout req %d: nltype %d seq %d, tid %llx\n",
			  i, ctl.reqs[i].nltype, ctl.reqs[i].nlseq, ctl.reqs[i].tid);
		__req_slot_release(&ctl.reqs[i]);
		if (++cleared >= PR_PENDING_CLEAR_NUM)
			break;
	}
out:
	pthread_mutex_unlock(&ctl.lock);
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

	if (!uport->sm_lid || (uport->sm_lid == 0xffff)) {
		path_err("%s/%d: Not able to resolve as sm_lid is not set: %u\n",
		msg->rheader.device_name, msg->rheader.port_num,
		uport->sm_lid);
		return EINVAL;
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
	path_dbg("Get req from %s/%d: slot %d, tid 0x%llx, nlseq 0x%x, path_use %d\n",
		 msg->rheader.device_name, msg->rheader.port_num, reqid, req->tid,
		 req->nlseq, req->nltype, msg->rheader.path_use);

	umad_set_addr(umad, uport->sm_lid, 1, uport->sm_sl, UMAD_QKEY);

	err = req_nlmsg_resolve_path(msg, &pr, &req->comp_mask);
	if (err)
		goto fail_resolve_path;

	sa = umad_get_mad(umad);
	build_mad_getPR(&pr, req->tid, req->comp_mask, sa);
	err = umad_send(uport->portid, uport->agentid, umad, len, PR_TIMEOUT, 0);
	if (err)
		path_err("umad_send failed %d\n", err);

	free(umad);
	clear_timeout_req();
	return err;

fail_resolve_path:
	req_slot_release(req);
fail_req_slot:
	free(umad);
	clear_timeout_req();
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

#define IB_LID_PERMISSIVE 65535

/* flid is embedded in gid:
 * | 10b | 22b of 0 | 16b of FLID | 16b of SubNet Prefix | 64b of EUI |
 */
static __u16 get_flid_from_gid(union ibv_gid *gid)
{
	return htobe16(*(__u16*)(gid->raw + 4));
}

static void set_pr_unidir(struct nl_pr *pr, struct umad_sa_packet *sa,
			  __u16 sflid, __u16 dflid, int flags)
{
	struct ibv_path_record *path;

	path = (struct ibv_path_record *)pr->rec.path_rec;
	pr->attr.nla_type = LS_NLA_TYPE_PATH_RECORD;
	pr->attr.nla_len = sizeof(*pr);
	pr->rec.flags = flags;
	memcpy(path, sa->data, sizeof(*pr));

	path->reversible_numpath = 0;
	if (flags & IB_PATH_OUTBOUND) {
		path->dlid = htobe16(dflid);
		path_info("outbound: slid %d, dlid %d\n", be16toh(path->slid), dflid);
	} else {
		path->slid = htobe16(IB_LID_PERMISSIVE);
		path->dlid = htobe16(sflid);
		path_info("inbound: slid %d, dlid %d\n", IB_LID_PERMISSIVE, sflid);
	}
}

static int send_resp(struct ib_user_mad *umad,
		     struct umad_sa_packet *sa,
		     uint32_t type, uint32_t seq, uint8_t path_use)
{
	struct nl_msg resp = {};
	struct nl_pr *pr = (struct nl_pr *)resp.data;
	struct ibv_path_record *path;
	int datalen, tlen = 0, ret;
	__u16 sflid, dflid;

	pr->attr.nla_type = LS_NLA_TYPE_PATH_RECORD;
	pr->attr.nla_len = sizeof(*pr);
	pr->rec.flags = get_rec_flags(path_use);
	memcpy(pr->rec.path_rec, sa->data, sizeof(*pr));
	tlen += sizeof(*pr);
	pr++;

	path = (struct ibv_path_record *)sa->data;
	path_dbg("SM PR slid %d, dlid %d, hoplimit %d\n",
		 be16toh(path->slid), be16toh(path->dlid),
		 be32toh(path->flowlabel_hoplimit) & 0xff);

	if ((path_use == LS_RESOLVE_PATH_USE_ALL) &&
	    ((be32toh(path->flowlabel_hoplimit) & 0xff) > 1)) {
		sflid = get_flid_from_gid(&path->sgid);
		dflid = get_flid_from_gid(&path->dgid);
		if (sflid && dflid) {
			set_pr_unidir(pr, sa, sflid, dflid,
				      IB_PATH_PRIMARY | IB_PATH_INBOUND);
			tlen += sizeof(*pr);
			pr++;

			set_pr_unidir(pr, sa, sflid, dflid,
				      IB_PATH_PRIMARY | IB_PATH_OUTBOUND);
			tlen += sizeof(*pr);
			pr++;
		}
	}

	resp.nlmsg_hdr.nlmsg_len = NLMSG_HDRLEN + tlen;
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

	path_dbg("mad received len %d: agent_id 0x%x, status 0x%x, timeout_ms 0x%x, length 0x%x,"
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

static void port_up(struct arr_port *aport)
{
	if (aport->activated)
		path_resolve_clean_one(aport);
	path_resolve_init_one(aport);
}

static void port_change(struct ibv_context *ibctx,
			struct arr_port *aport)
{
	struct ibv_port_attr port_attr = {};
	int err;

	err = ibv_query_port(ibctx, aport->uport->portnum, &port_attr);
	if (err) {
		path_err("ibv_query_port failed %s/%d: %d\n",
			 aport->uport->ca_name, aport->uport->portnum);
		return;
	}

	aport->uport->sm_lid = port_attr.sm_lid;
	aport->uport->sm_sl = port_attr.sm_sl;
	path_info("%s/%d: Update sm_lid %u, sm_sl %u\n",
		  aport->uport->ca_name, aport->uport->portnum,
		  aport->uport->sm_lid, aport->uport->sm_sl);

	port_up(aport);
}

static void ibdev_event_handler(int devid)
{
	struct ibv_async_event event;
	struct arr_port *aport;
	int ret;

	ret = ibv_get_async_event(arrdevs[devid].ibctx, &event);
	if (ret) {
		path_err("ibdev %d: Get async event failed: %d\n", devid, errno);
		return;
	}

	path_info("%s/%d: Get event %d\n",
		  arrdevs[devid].name, event.element.port_num, event.event_type);

	if (event.element.port_num > arrdevs[devid].port_cnt) {
		path_err("%s/%d: invalid port num, max %d\n",
			 arrdevs[devid].name, event.element.port_num, arrdevs[devid].port_cnt);
		goto out;
	}

	aport = &arrdevs[devid].ports[event.element.port_num - 1];
	if (aport->link_layer != IBV_LINK_LAYER_INFINIBAND)
		goto out;

	switch (event.event_type) {
	case IBV_EVENT_PORT_ACTIVE:
		port_up(aport);
		break;

	case IBV_EVENT_LID_CHANGE:
	case IBV_EVENT_GID_CHANGE:
	case IBV_EVENT_PKEY_CHANGE:
	case IBV_EVENT_CLIENT_REREGISTER:
		port_change(arrdevs[devid].ibctx, aport);
		break;

	case IBV_EVENT_PORT_ERR:
		path_resolve_clean_one(aport);
		break;

	default:
		break;
	}

out:
	ibv_ack_async_event(&event);
}

void *run_path_resolve(void *arg)
{
	int i, j, fd_num, err;
	struct pollfd *fds;

	if (!umad_port_num) {
		path_err("path resolve not initialized\n");
		return NULL;
	}

	fd_num = umad_port_num + ibdev_num;
	fds = calloc(fd_num, sizeof(*fds));
	if (!fds) {
		path_err("calloc %d+%d failed: %d\n",
			 umad_port_num, ibdev_num, errno);
		return NULL;
	}

	/**
	 * [0, umad_port_num): umad events;
	 * [umad_port_num, fd_num): ibdev async events
	 */
	for (i = 0, j = 0; i < umad_port_num; i++, j++) {
		fds[j].fd = umad_get_fd(uports[i].portid);
		fds[j].events = POLLIN;
		err = set_fd_block(fds[j].fd);
		if (err)
			path_warn("%s/%d: umad fd %d is blocking\n",
				  uports[j].ca_name, uports[j].portnum, fds[j].fd);

		path_dbg("fds %d: umad_port %d\n", j, i);
	}

	for (i = 0; i < ibdev_num; i++, j++) {
		fds[j].fd = arrdevs[i].ibctx->async_fd;
		fds[j].events = POLLIN;
		err = set_fd_block(fds[j].fd);
		if (err)
			path_warn("ibdev %d async_fd is blocking\n", i);

		path_dbg("fds %d: ibdev %d\n", j, i);
	}

	do {
		err = poll(fds, fd_num, -1);
		if (err < 0) {
			path_err("poll error %d\n", errno);
			continue;
		}

		for (i = 0; i < fd_num; i++) {
			if (!fds[i].revents)
				continue;

			if (!(fds[i].revents & POLLIN)) {
				fds[i].revents = 0;
				continue;
			}

			if (i < umad_port_num)
				recv_one_mad(i);
			else
				ibdev_event_handler(i - umad_port_num);

			fds[i].revents = 0;
		}

	} while (1);

	return NULL;
}
