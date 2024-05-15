BUILD_TARGET ?= debug
export BUILD_TARGET

RTE_SRCDIR ?= $(shell pwd)
CURDIR ?= $(shell pwd)
BASE_OUTPUT ?= $(shell pwd)
CUR_SUBDIR ?= build
# by default we build in build/
O ?= $(RTE_SRCDIR)/build

PKGCONF ?= pkg-config

ifeq ($(shell $(PKGCONF) --exists libdpdk && echo 0),0)
CFLAGS += $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS += $(shell $(PKGCONF) --static --libs libdpdk)
else
$(error "DPDK not found, please ensure it is installed and pkg-config is configured")
endif

EXTRA_CFLAGS +=  -W -Wall -g3 -gdwarf-2 -O3

EXTRA_CFLAGS += $(CFLAGS)
ifeq ($(BUILD_TARGET),qemu)
EXTRA_CFLAGS +=  -DPKTJ_DEBUG -DPKTJ_QEMU -DL3FWDACL_DEBUG -DRTE_LOG_LEVEL=8
endif
ifeq ($(BUILD_TARGET),release)
EXTRA_CFLAGS +=  -DRTE_LOG_LEVEL=3
endif
ifeq ($(BUILD_TARGET),debug)
EXTRA_CFLAGS +=  -DPKTJ_DEBUG -DRTE_LOG_LEVEL=8 -DL3FWDACL_DEBUG
endif

EXTRA_CFLAGS += -DALLOW_EXPERIMENTAL_API
EXTRA_CFLAGS += -Wno-implicit-fallthrough
EXTRA_LDFLAGS += $(LDFLAGS)

export EXTRA_CFLAGS

DIRS-y += lib
DIRS-y += app
DIRS-y += tests

DEPDIRS-tests = lib

.PHONY: default
default: all

.PHONY: all
all: $(DIRS-y)

.PHONY: clean
clean: $(DIRS-y)

.PHONY: test
test: default

.PHONY: help
help:
	@cat doc/build-commands.txt

# we use clang-format-3.7, format your code before commiting
.PHONY: format
format:
	clang-format -i */*.h */*.c

.PHONY: $(DIRS-y)
$(DIRS-y):
	@echo "== $@"
	@$(Q) $(MAKE) -C $(@) \
                M=$(CURDIR)/$(@)/Makefile \
                BASE_OUTPUT=$(BASE_OUTPUT) \
                CUR_SUBDIR=$(CUR_SUBDIR)/$(@) \
                S=$(CURDIR)/$(@) \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		EXTRA_LDFLAGS="$(LDFLAGS)" \
                $(filter-out $(DIRS-y),$(MAKECMDGOALS))
