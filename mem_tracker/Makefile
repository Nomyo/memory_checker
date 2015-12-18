CXX=g++
CC=gcc

CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g -fPIC -ldl
CFLAGS=-std=c99 -Wall -Werror -Wextra -g -fPIC -ldl

CLIBFLAGS= -shared

SRC = mem_tracker.cc h_rdebug.cc break.cc tools.cc syscall_p.cc m_trace.cc
LSRC = myliballoc.c
LIB = myliballoc.so

all: $(SRC) $(LIB)
			$(CXX) $(CXXFLAGS) -lcapstone -o mem_tracker $(SRC)

$(LIB): $(LSRC)
	$(CC) $(CLIBFLAGS) $(CFLAGS) -o $@ $^

clean:
	rm -f mem_tracker
	rm -f $(LIB)
