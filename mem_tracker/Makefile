CXX=g++
CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g
SRC=mem_tracker.cc h_rdebug.cc break.cc tools.cc syscall_p.cc m_trace.cc

all: $(SRC)
	$(CXX) $(CXXFLAGS) -lcapstone -o mem_tracker $(SRC)

clean:
	rm -f mem_strace
