
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

$(APPS): LIBS := -L. -lsfnettest -lm -lrt
$(APPS): libsfnettest.a


# TODO: Make this stuff VPATH friendly.
SFNT_SRC_CSUM	:= $(shell cat *.c *.h | md5sum | sed 's/ .*//')
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


include rules.mk
