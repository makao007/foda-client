CC = gcc
LIBS = -lpcap
CFLAGS = -Wall -g -O1

zdclient	: md5.o zdclient.o
	$(CC) $(CFLAGS) -o $@ md5.o zdclient.o $(LIBS)

md5.o	: md5.c md5.h
	$(CC) $(CFLAGS) -c $<

zdclient.o : zdclient.c
	$(CC) $(CFLAGS) -c $<
	
clean :
	rm -v *.o *~ zdclient
