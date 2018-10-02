CC=gcc
CFLAGS=-I. -g

test: test.o
	$(CC) -o test test.o -lpthread

check: test
	bash -c "./run.sh"

clean:
	rm core test.o test
