include rules_pre.mk


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

ifdef OS_MACOSX
NETTEST_SRCS	+= sfnt_macosx
endif

libsfnettest.a: $(NETTEST_SRCS:%=%.o)

# This file needs -fPIC due to the dynamic symbol magic it uses to detect
# the presence/version of OpenOnload.
sfnt_sysinfo.o: CFLAGS += -fPIC


# Set libraries to link against
LIBS := -L. -lsfnettest -lm 
ifdef OS_SUNOS
LIBS += -lsocket -lnsl
endif
ifndef OS_MACOSX
LIBS += -lrt
endif
ifdef OS_LINUX
LIBS += -lonload_ext -ldl
endif
ifdef USE_ZF
LIBS += -lonload_zf
endif
sfnt-stream: LIBS += -lpthread
$(APPS): libsfnettest.a


# TODO: Make this stuff VPATH friendly.
SFNT_SRC_CSUM	:= $(shell find . -name '*.[ch]' | LC_ALL=C sort | \
                             xargs cat | $(MD5SUM) | sed 's/ .*//')
sinclude version.mk
ifeq ($(SFNT_VERSION),)

SFNT_VERSION	:= $(shell hg id --id 2>/dev/null || \
  ( test -f ../.hg_archival.txt && \
    awk -n '/node:/{print $$2}' ../.hg_archival.txt ) || \
  echo no-version)
else
ifneq ($(SFNT_RELEASE_CSUM),$(SFNT_SRC_CSUM))
SFNT_VERSION	:= $(SFNT_VERSION)-modified
endif
endif
CPPFLAGS	+= -DSFNT_VERSION='"$(SFNT_VERSION)"'
CPPFLAGS	+= -DSFNT_SRC_CSUM='"$(SFNT_SRC_CSUM)"'
ifdef USE_ZF
CPPFLAGS	+= -DUSE_ZF
endif

ifdef ONLOAD_TREE
LINK_ONLOAD_EXT	:= \
	-L$(ONLOAD_TREE)/build/$(shell mmaketool --userbuild)/lib/onload_ext \
	-Wl,-rpath,$(ONLOAD_TREE)/build/$(shell mmaketool --userbuild)/lib/onload_ext
LINK_ONLOAD_ZF	:= \
	-L$(ONLOAD_TREE)/build/$(shell mmaketool --userbuild)/lib/zf \
	-Wl,-rpath,$(ONLOAD_TREE)/build/$(shell mmaketool --userbuild)/lib/zf
sfnt-pingpong.o: CPPFLAGS += -I$(ONLOAD_TREE)/src/include
sfnt-stream.o:   CPPFLAGS += -I$(ONLOAD_TREE)/src/include
sfnt_mux.o:      CPPFLAGS += -I$(ONLOAD_TREE)/src/include
sfnt-pingpong: LIBS := $(LINK_ONLOAD_EXT) $(LINK_ONLOAD_ZF) $(LIBS)
sfnt-stream:   LIBS := $(LINK_ONLOAD_EXT) $(LINK_ONLOAD_ZF) $(LIBS)
endif

# Define MSG_WAITALL_HACK to avoid using MSG_WAITALL, which is not
# supported by at least one kernel-bypass stack.
ifdef MSG_WAITALL_HACK
CPPFLAGS	+= -include sfnettest_waitall_hack.h
endif


include rules.mk
