CXX=g++
CC=gcc

CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g -fPIC -ldl
CFLAGS=-std=c99 -Wall -Werror -Wextra -g -fPIC -ldl

CLIBFLAGS= -shared

SRC = src/mem_tracker.cc src/h_rdebug.cc src/break.cc src/tools.cc \
			src/syscall_p.cc src/m_trace.cc
LSRC = src/myliballoc.c
LIB = myliballoc.so

all: $(SRC) $(LIB)
			$(CXX) $(CXXFLAGS) -lcapstone -o mem_tracker $(SRC)

$(LIB): $(LSRC)
	$(CC) $(CLIBFLAGS) $(CFLAGS) -o $@ $^

check: all
	gcc ./tests/test.c -o test
	./mem_tracker --preload ./myliballoc.so ./test

clean:
	$(RM) mem_tracker
	$(RM) $(LIB)
	$(RM) test
