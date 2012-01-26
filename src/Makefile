
APPS		:= sfnt-pingpong sfnt-stream
DEFAULT		:= $(APPS)
ALL		:= $(APPS)


.PHONY: default
default: $(DEFAULT)

.PHONY: all
all: $(ALL)

.PHONY: clean
clean:
	find . -name "*.o" | xargs rm -f
	find . -name "*.d" | xargs rm -f
	find . -name "*.a" | xargs rm -f
	rm -f $(ALL)


NETTEST_SRCS	:= sfnt_sysinfo	\
		sfnt_logging	\
		sfnt_cmd_line	\
		sfnt_test	\
		sfnt_socket	\
		sfnt_stats	\
		sfnt_tsc	\
		sfnt_int_list	\
		sfnt_affinity	\
		sfnt_mux	\
		sfnt_fd		\

libsfnettest.a: $(NETTEST_SRCS:%=%.o)

# This file needs -fPIC due to the dynamic symbol magic it uses to detect
# the presence/version of OpenOnload.
sfnt_sysinfo.o: CFLAGS += -fPIC


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


# Set libraries to link against
LIBS := -L. -lsfnettest -lm 
ifdef OS_SUNOS
LIBS += -lsocket -lnsl
endif
ifndef OS_MACOSX
LIBS += -lrt
endif
sfnt-stream: LIBS += -lpthread
$(APPS): libsfnettest.a


# TODO: Make this stuff VPATH friendly.
SFNT_SRC_CSUM	:= $(shell find . -name '*.[ch]' | LC_ALL=C sort | \
                             xargs cat | $(MD5SUM) | sed 's/ .*//')
sinclude version.mk
ifeq ($(SFNT_VERSION),)
SFNT_VERSION	:= $(shell hg id --id 2>/dev/null || echo no-version)
else
ifneq ($(SFNT_RELEASE_CSUM),$(SFNT_SRC_CSUM))
SFNT_VERSION	:= $(SFNT_VERSION)-modified
endif
endif
CPPFLAGS	+= -DSFNT_VERSION='"$(SFNT_VERSION)"'
CPPFLAGS	+= -DSFNT_SRC_CSUM='"$(SFNT_SRC_CSUM)"'

# Define MSG_WAITALL_HACK to avoid using MSG_WAITALL, which is not
# supported by at least one kernel-bypass stack.
ifdef MSG_WAITALL_HACK
CPPFLAGS	+= -include sfnettest_waitall_hack.h
endif


include rules.mk
