sfnt-pingpong
=============

Introduction
------------

`sfnt-pingpong` measures ping-pong latency over a range of message sizes,
using the following network and IPC mechanisms:

- TCP sockets
- UDP sockets
- UNIX stream sockets
- UNIX datagram sockets
- pipes

Measuring network latency
-------------------------

To measure latency over a network, first start a "server" instance on one
node:

```console
host1$ sfnt-pingpong
```

Then start a "client" instance on another node, passing the name of the
server node as follows:

```console
host2$ sfnt-pingpong tcp host1 # for TCP

host2$ sfnt-pingpong udp host1 # for UDP

host2$ sfnt-pingpong --mcastintf=ethX udp host1 # for UDP multicast
```

Measuring IPC latency
---------------------

For pipes and unix domain sockets (and for inet sockets using the loopback
interface), there is no need to run a separate server process.

```sh
sfnt-pingpong pipe

sfnt-pingpong unix_stream

sfnt-pingpong unix_datagram
```

Options
-------

There are numerous options to control details of the test.  Options are
given on the client's command line -- the server side should be invoked
with no arguments.  Some options apply only on the client side, and others
apply to both client and server.  For options that apply to both sides,
you can either supply a single value that is used on both the client and
server. eg:

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
sfnt-pingpong --help
```

---

Copyright (c) 2011-2023 Advanced Micro Devices, Inc.
