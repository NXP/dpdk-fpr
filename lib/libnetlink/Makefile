
LIB= libnetlink.a

CFLAGS += -I$(S)
CFLAGS += -I$(S)/../../include/

SRCS-y += netlink.c

SYMLINK-y-include += libnetlink.h

LIBABIVER=1
EXPORT_MAP := libnetlink.map

OBJS-y := $(SRCS-y:.c=.o)

all : $(LIB)
$(LIB) : $(OBJS-y)
	$(AR) rcs $@ $^

%.o : %.c
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -c $< -o $@

clean :
	rm -rf $(OBJS-y) $(LIB)

.PHONY : all clean
