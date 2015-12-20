CXX=g++
CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g
SRC= src/my_memtrace.cc src/syscall_p.cc

all: $(SRC)
	$(CXX) $(CXXFLAGS) -o mem_strace $(SRC)

clean:
	$(RM) mem_strace
