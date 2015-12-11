CXX=g++
CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g
SRC=strace_hook.cc track.cc

all: $(SRC)
	$(CXX) $(CXXFLAGS) -o mem_strace $(SRC)

clean:
	rm -f mtrace
