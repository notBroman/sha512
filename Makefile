CC	:= gcc
CFLAGS	:= -c -std=c17 -O3
LFLAGS	:= -Wall -Wextra -Werror -pedantic -O3 -std=c17
DBGFLAGS:= -g


all : build run

build : main.o mysha512.o
	$(CC) $(LFLAGS) main.o mysha512.o -o sha.out

main.o : main.c
	$(CC) $(CFLAGS) main.c

mysha512.o : mysha512.c mysha512.h
	$(CC) $(CFLAGS) mysha512.c

clean:
	rm -rf *.o

run:
	./sha.out
