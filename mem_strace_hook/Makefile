CXX=g++
CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g
SRC=strace_hook.cc track.cc break.cc tools.cc syscall_p.cc

all: $(SRC)
	$(CXX) $(CXXFLAGS) -lcapstone -o mem_strace_hook $(SRC)

clean:
	$(RM) mem_strace_hook
