APP = test_libneighbour

NS := $(shell mktemp -u -t XXXXXX | sed 's@/tmp/@@')

SRCS-y += a.c

CFLAGS += -I$(BASE_OUTPUT)/lib/libneighbour/
CFLAGS += -I$(S)/../../include/

LDFLAGS += -L$(BASE_OUTPUT)/lib/libneighbour/ -lneighbour

.PHONY: default
default: all

OBJS := $(SRCS-y:.c=.o)

all : $(APP)
$(APP) : $(OBJS)
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(EXTRA_LDFLAGS)

%.o : %.c
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -c $< -o $@

clean :
	rm -rf $(OBJS) $(LIB) $(APP)

.PHONY : all clean

