CXX=g++
CC=gcc

CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g -fPIC -ldl
CFLAGS=-std=c99 -Wall -Werror -Wextra -g -fPIC -ldl

CLIBFLAGS= -shared

SRC = mem_checker.cc h_rdebug.cc break.cc tools.cc m_trace.cc m_access.cc
LSRC = myliballoc.c
LIB = myliballoc.so

all: $(SRC) $(LIB)
			$(CXX) $(CXXFLAGS) -lcapstone -o mem_checker $(SRC)

$(LIB): $(LSRC)
	$(CC) $(CLIBFLAGS) $(CFLAGS) -o $@ $^

clean:
	$(RM) mem_checker
	$(RM) $(LIB)
