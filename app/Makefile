# binary name
APP = dpdk-fpr

# all source are stored in SRCS-y
SRCS-y := main.c 
SRCS-y += control.c
SRCS-y += kni.c
SRCS-y += cmdline.c
SRCS-y += acl.c
SRCS-y += config.c
SRCS-y += cmdline_helpers.c

CFLAGS += $(WERROR_FLAGS)
CFLAGS += -I$(S)/../lib/libneighbour/
CFLAGS += -I$(S)/../lib/libnetlink/

DEPDIR-y += lib/libnetlink lib/libneighbour

APP_LDFLAGS += -lc -lpthread -ldl
APP_LDFLAGS += -L$(BASE_OUTPUT)/lib/libneighbour/ -L$(BASE_OUTPUT)/lib/libnetlink/ -lneighbour -lnetlink
ifeq ($(BUILD_TARGET),qemu)
	APP_LDFLAGS += --wrap=virtio_recv_mergeable_pkts
endif

APP_LDFLAGS += $(EXTRA_LDFLAGS)

# workaround for a gcc bug with noreturn attribute
# http://gcc.gnu.org/bugzilla/show_bug.cgi?id=12603
ifeq ($(CONFIG_RTE_TOOLCHAIN_GCC),y)
CFLAGS_main.o += -Wno-return-type
endif

.PHONY: default test
default: all
test:

OBJS := $(SRCS-y:.c=.o)

all : $(APP)
$(APP) : $(OBJS)
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -o $@ $(OBJS) $(APP_LDFLAGS)

%.o : %.c
	$(CC) $(EXTRA_CFLAGS) $(CFLAGS) -c $< -o $@

clean :
	rm -rf $(APP) $(OBJS) $(LIB)

.PHONY : all clean
