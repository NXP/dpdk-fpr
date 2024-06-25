APP = test_libneighbour

NS := $(shell mktemp -u -t XXXXXX | sed 's@/tmp/@@')

SRCS-y += a.c

CFLAGS += -I$(BASE_OUTPUT)/lib/libneighbour/
CFLAGS += -I$(S)/../../include/

TESTNEIGH_LDFLAGS += -L$(BASE_OUTPUT)/lib/libneighbour/ -lneighbour
TESTNEIGH_LDFLAGS += $(EXTRA_LDFLAGS)

.PHONY: default
default: all

OBJS := $(SRCS-y:.c=.o)

all : $(APP)
$(APP) : $(OBJS)
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $(OBJS) $(TESTNEIGH_LDFLAGS)

%.o : %.c
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -c $< -o $@

clean :
	rm -rf $(OBJS) $(LIB) $(APP)

.PHONY : all clean

