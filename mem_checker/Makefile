CXX=g++
CC=gcc

CXXFLAGS=-std=c++11 -pedantic -Wall -Werror -Wextra -g -fPIC -ldl
CFLAGS=-std=c99 -Wall -Werror -Wextra -g -fPIC -ldl

CLIBFLAGS= -shared

SRC = src/mem_checker.cc src/h_rdebug.cc src/break.cc src/tools.cc \
			src/m_trace.cc src/m_access.cc
LSRC = src/myliballoc.c
LIB = myliballoc.so

all: $(SRC) $(LIB)
			$(CXX) $(CXXFLAGS) -lcapstone -o mem_checker $(SRC)

$(LIB): $(LSRC)
	$(CC) $(CLIBFLAGS) $(CFLAGS) -o $@ $^

clean:
	$(RM) mem_checker
	$(RM) $(LIB)
