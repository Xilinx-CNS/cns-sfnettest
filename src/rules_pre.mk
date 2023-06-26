# SPDX-License-Identifier: GPL-2.0-only
# SPDX-FileCopyrightText: Copyright (c) 2011 Solarflare Communications Inc.

# Set per OS flags
ifeq ($(shell uname -s),Linux)
OS_LINUX := 1
MD5SUM := md5sum
endif
ifeq ($(shell uname -s),Darwin)
OS_MACOSX := 1
MD5SUM := md5
endif
ifeq ($(shell uname -s),SunOS)
OS_SUNOS := 1
MD5SUM := digest -a md5
endif
ifeq ($(shell uname -s),FreeBSD)
OS_FREEBSD := 1
MD5SUM := md5
endif
