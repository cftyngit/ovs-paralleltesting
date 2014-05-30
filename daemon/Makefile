all: release

CFLAGS := -Wall -O2

ifdef daemon
	CFLAGS := -DDAEMONIZE
endif

release: main.c network.o network.h
	$(CC) -Wall -o ovspd main.c network.o $(CFLAGS) -DNDEBUG
debug: main.c network.o network.h
	$(CC) -Wall -o ovspd main.c network.o $(CFLAGS)
network.o: network.c 
	$(CC) -Wall -c network.c
clean:	
	rm -rf *.o ovspd
dep:
	g++ -M *.c > .dep