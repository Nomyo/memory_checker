CXX=g++
CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g
SRC=my_memtrace.cc syscall_p.cc

all: $(SRC)
	$(CXX) $(CXXFLAGS) -o mem_strace $(SRC)

clean:
	$(RM) mem_strace
