CXX=g++
CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g
SRC=src/strace_hook.cc src/track.cc src/break.cc src/tools.cc \
		src/syscall_p.cc

all: $(SRC)
	$(CXX) $(CXXFLAGS) -lcapstone -o mem_strace_hook $(SRC)

clean:
	$(RM) mem_strace_hook
