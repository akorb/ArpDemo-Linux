CC=gcc
CFLAGS=-Wall

all:
	$(CC) $(CFLAGS) -o arp arp.c

clean:
	rm arp
