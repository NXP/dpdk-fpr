DIRS-y += libneighbour
DIRS-y += libnetlink

.PHONY: default test
default: all
test:

.PHONY: all
all: $(DIRS-y)

.PHONY: clean
clean: $(DIRS-y)

.PHONY: $(DIRS-y)
$(DIRS-y):
	@echo "== $@"
	@$(Q)$(MAKE) -C $(@) \
                M=$(CURDIR)/$(@)/Makefile \
                BASE_OUTPUT=$(BASE_OUTPUT) \
                CUR_SUBDIR=$(CUR_SUBDIR)/$(@) \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		EXTRA_LDFLAGS="$(EXTRA_LDFLAGS)" \
                S=$(CURDIR)/$(@) \
                $(filter-out $(DIRS-y),$(MAKECMDGOALS))
