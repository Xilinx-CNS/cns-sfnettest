
CFLAGS		+= -Wall -Werror

ifdef OS_LINUX
# Add symbols to dynamic symbol table.  This is necessary to allow
# detection of onload in sfnt_sysinfo.c
CCLINKFLAGS	+= -Wl,-E
else
CCLINKFLAGS	+= -Wl
endif


# Disable built-in rules.
%: %.c
%: %.o

%.a:
	$(AR) -r $@ $?

# Build app from object file with same name.
%: %.o
	$(CC) $(CCLINKFLAGS) $(CFLAGS) $< $(LIBS) -o $@
