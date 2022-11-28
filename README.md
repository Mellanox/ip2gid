# Nvidia address and route userspace resolution services for Infiniband

This is a userspace application that interacts over NetLink with the Linux
RDMA subsystem and provides 2 services: ip2gid (address resolution) and gid2lid (PathRecord resolution).

## ip2gid
It resolves a destination IP into a destination GID needed when running a rdmacm applications.

The application is both a client and a server and should be run on every
node in the fabric.

This is needed when rdmacm is used to initiate IB traffic between nodes
on different IP subnets.

Rdmacm works over IB fabrics by finding the L2 address (using ARP) of the node
that corresponds to the destination IP and sending a CM request to to that L2/GID.
The GID is used by IPoIB with a UD QP which then can pass the CM request to the
relevant RDMA device.

As ARP between IPs on different subnets returns the NEXT-HOP L2 address and not
the end node's, a different solution is needed in such cases.

Ip2gid address this limitation by using a dedicated protocol on top of UDP
to send and answer for IP 2 GID resolution requests.

## gid2lid
It resolves a GID into one PathRecord(PR) or multiple PRs if needed. It works like this:
- Get a request from kernel;
- Forward this request to SM, and get response;
- Check if multiple PRs are needed; If yes then it creates another 2 PRs, and send them to kernel along with the default (GMP) one.
This service is useful for Floating LID (FLID) support, where multiple PRs are needed.

# Building
```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
```

*build* will contain the executable *ibarr*.

# Running
Just run, as root:

`ibarr`

Output is logged to the standard output by default.

If you want to enable logging, use the option *-l* . Note that log level 0
logs everything and higher levels log just some of the messages:

`ibarr -l 0`

Alternatively, you can start the systemd unit. It will not be started
automatically:

`systemctl start ip2gid`

Output will be logged to the journal:

`journalctl -u ip2gid`


### Debian Derived
```sh
$ apt-get install build-essential cmake libnl-3-dev libnl-route-3-dev libibverbs-dev libibumad-dev pkgconf
```

### Fedora
```sh
$ dnf install cmake gcc libnl3-devel rdma-core-devel
```
