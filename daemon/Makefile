all: release

CFLAGS := -Wall -O2

ifdef daemon
	CFLAGS := -DDAEMONIZE
endif

cmd2: ovsptd_cmd.cpp ovsptd_nlmgr.o ovsptd_nlmgr.h
	$(CXX) -Wall -o ovsptd_cmd ovsptd_cmd.cpp ovsptd_nlmgr.o $(CFLAGS)
cmd: ovsptd_cmd.c ovsptd_nlmgr.o ovsptd_nlmgr.h
	$(CXX) -Wall -o ovsptd_cmd ovsptd_cmd.c ovsptd_nlmgr.o $(CFLAGS)
release: main.c network.o network.h
	$(CC) -Wall -o ovspd main.c network.o $(CFLAGS) -DNDEBUG
debug: main.c network.o network.h
	$(CC) -Wall -o ovspd main.c network.o $(CFLAGS)
network.o: network.c 
	$(CC) -Wall -c network.c
ovsptd_nlmgr.o: ovsptd_nlmgr.c
	$(CXX) -Wall -c ovsptd_nlmgr.c
clean:	
	rm -rf *.o ovspd ovsptd_cmd
dep:
	$(CC) -M *.c > .dep