# IP2GID Userspace resolution over UDP

This is a userspace application that interacts over NetLink with the Linux
RDMA subsystem and helps with the task of resolving a destination IP into
a destination GID needed when running a rdmacm applications.

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

# Building
```sh
$ mkdir build
$ cd build
$ cmake ..
$ make
```

*build* will contain the executable *ip2gid*.

### Debian Derived
```sh
$ apt-get install build-essential cmake gcc libnl-3-dev libnl-route-3-dev
```

### Fedora
```sh
$ dnf install cmake gcc libnl3-devel
```
