UNAME_S := $(shell uname -s)


CC := g++

ifeq ($(UNAME_S),Darwin)
	CC := clang++
endif


all: compile

compile: dns.h main.cpp
	$(CC) -o dns_parser -g main.cpp

test: dns.h dns_test.cpp
	$(CC) -o dns_test -g dns_test.cpp && ./dns_test

clean: 
	rm -rf dns_parser dns_test


