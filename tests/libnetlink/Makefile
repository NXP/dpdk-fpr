APP = test_libnetlink

NS := $(shell mktemp -u -t XXXXXX | sed 's@/tmp/@@')

SRCS-y += a.c

CFLAGS += -I$(BASE_OUTPUT)/lib/libnetlink/
CFLAGS += -I$(S)/../../include/

LDFLAGS += -L$(BASE_OUTPUT)/lib/libnetlink/ -lnetlink

.PHONY: default
default: all

#include $(RTE_SDK)/mk/rte.extapp.mk
OBJS := $(SRCS-y:.c=.o)

all : $(APP)
$(APP) : $(OBJS)
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS) $(EXTRA_LDFLAGS)

%.o : %.c
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -c $< -o $@

clean :
	rm -rf $(OBJS) $(LIB) $(APP)

.PHONY : all clean
