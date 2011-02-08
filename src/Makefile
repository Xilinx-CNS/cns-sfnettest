
APPS		:= sfnt-pingpong
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

sfnt-pingpong: LIBS := -L. -lsfnettest -lm
sfnt-pingpong: libsfnettest.a


# TODO: Make this stuff VPATH friendly.
sinclude version.mk
ifeq ($(SFNT_VERSION),)
SFNT_VERSION	:= $(shell hg id --id || echo no-version)
endif
SFNT_SRC_CSUM	:= $(shell cat *.c *.h | md5sum | sed 's/ .*//')
CPPFLAGS	+= -DSFNT_VERSION='"$(SFNT_VERSION)"'
CPPFLAGS	+= -DSFNT_SRC_CSUM='"$(SFNT_SRC_CSUM)"'


include rules.mk
