
LIB = libneighbour.a

CFLAGS += -I$(S)
CFLAGS += -I$(S)/../../include/

SRCS-y += neighbour.c

SYMLINK-y-include += libneighbour.h

LIBABIVER=1
EXPORT_MAP := libneighbour.map

OBJS-y := $(SRCS-y:.c=.o)

all : $(LIB)
$(LIB) : $(OBJS-y)
	$(AR) rcs $@ $^

%.o : %.c
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -c $< -o $@

clean :
	rm -rf $(OBJS-y) $(LIB)

.PHONY : all clean
