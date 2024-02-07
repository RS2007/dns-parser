all: compile

compile: dns.h main.cpp
	g++  -o dns_parser -g main.cpp

test: dns.h dns_test.cpp
	g++  -o dns_test -g dns_test.cpp && ./dns_test

clean: 
	rm -rf dns_parser dns_test
