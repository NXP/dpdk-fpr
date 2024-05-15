
DIRS-y += libneighbour
DIRS-y += libnetlink

.PHONY:test default
default: all
test:
	$(Q)for dir in $(DIRS-y); do\
		[ "x$(ONLY_TEST)" != "x" ] && [ "$(ONLY_TEST)" != "$$dir" ] && continue;\
		echo "== $$dir";\
		$(MAKE) -C $$dir \
			M=$(CURDIR)/$$dir/Makefile \
			BASE_OUTPUT=$(BASE_OUTPUT) \
			CUR_SUBDIR=$(CUR_SUBDIR)/$$dir \
			S=$(CURDIR)/$$dir\
			EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
			EXTRA_LDFLAGS="$(EXTRA_LDFLAGS)" \
			test;\
	done

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
                S=$(CURDIR)/$(@) \
		EXTRA_CFLAGS="$(EXTRA_CFLAGS)" \
		EXTRA_LDFLAGS="$(EXTRA_LDFLAGS)" \
                $(filter-out $(DIRS-y),$(MAKECMDGOALS))

