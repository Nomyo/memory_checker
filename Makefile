all:
	$(MAKE) -C mem_checker/ all
	$(MAKE) -C mem_strace/ all
	$(MAKE) -C mem_strace_hook/ all
	$(MAKE) -C mem_tracker/ all

mem_strace:
	$(MAKE) -C $@/ all

mem_strace_hook:
	$(MAKE) -C $@/ all

mem_tracker:
	$(MAKE) -C $@/ all

mem_checker:
	$(MAKE) -C $@/ all

clean:
	$(MAKE) -C mem_checker/ clean
	$(MAKE) -C mem_strace/ clean
	$(MAKE) -C mem_strace_hook/ clean
	$(MAKE) -C mem_tracker/ clean

