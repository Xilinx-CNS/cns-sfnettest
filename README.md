
SfNetTest
=========

*sfnettest* is a suite of tools for measuring network performance developed
by Solarflare.  It differs from existing tools in some of the options it
provides, which allow probing of particular application behaviours.

Accelerate your network stack with [OpenOnload](https://github.com/Xilinx-CNS/onload).

This release supports Linux, Solaris, OSX and FreeBSD.

Building
--------

```sh
cd sfnettest-ver/src
make
```

Running
-------

Instructions on running each tool:

* [`sfnt-pingpong`](README.sfnt-pingpong.md)
* [`sfnt-stream`](README.sfnt-stream.md)

Container
---------

[Dockerfile](Dockerfile) includes both tools.

```sh
docker build --network=host -t sfnettest .
docker run --network=host sfnettest --help # sfnt-pingpong is default entrypoint
```

Copyright
---------

David Riddoch
2011/07/05

Copyright (c) 2011-2023 Advanced Micro Devices, Inc.
