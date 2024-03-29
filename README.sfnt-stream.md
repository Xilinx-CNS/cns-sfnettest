sfnt-stream
===========

Introduction
------------

`sfnt-stream` measures streaming latency for a fixed message size over a
range of message rates.  At time of writing it only works with UDP
sockets, but will be extended to support other protocols and IPC
mechanisms later.

Measuring network latency
-------------------------

To measure latency and message rate over a network, first start a "server"
instance on one node:

```console
host1$ sfnt-stream
```

Then start a "client" instance on another node, passing the name of the
server node as follows:

```console
host2$ sfnt-stream udp host1 # for UDP

host2$ sfnt-stream --mcastintf=ethX udp host1 # for UDP multicast
```

If running sfnt-stream with OpenOnload or EnterpriseOnload, we recommend
you enable the option `EF_STACK_PER_THREAD=1` at the client side (`host2`
above) for best performance.

Options
-------

There are numerous options to control details of the test.  Options are
given on the client's command line -- the server side should be invoked
with no arguments.  Some options apply only on the client side, and others
apply to both client and server.  For options that apply to both sides,
you can either supply a single value that is used on both the client and
server.  eg:

```sh
    --mcastintf=eth2          # use interface eth2 on client and server
```

Or you can give two values separated by `;`.  The first applies to the
client, and the second to the server.  eg:

```sh
    --mcastintf='eth2;eth3'   # use eth2 on client and eth3 on server
```

Note the quoting needed to prevent the shell from interpreting the `;`.

Here is a brief overview of the available options:

- An option to "spin" making non-blocking calls (`--spin`)
- An option to use select, poll or epoll for blocking (`--muxer`)
- Options to add more file descriptors to select, poll and epoll
  (`--n-pipe`, `--n-udp`, `--n-tcpc`, `--n-tcpl`)
- Options to control multicast (`--mcastintf`, `--mcast`, `--mcastloop`)
- An option to set CPU affinity (`--affinity`)

To get the full list, invoke:

```sh
sfnt-stream --help
```

---

Copyright (c) 2011-2023 Advanced Micro Devices, Inc.
