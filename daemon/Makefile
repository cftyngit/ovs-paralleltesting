all: cmd3

CFLAGS := -Wall -O2
CXXFLAGS := -Wall -O2 -pthread --std=c++11
ifdef daemon
	CFLAGS := -DDAEMONIZE
endif

cmd3: ovsptd_cmd1.cpp ovsptd_nlmgr.o ovsptd_nlmgr.h ovsptd_msgmgr.o ovsptd_msgmgr.h ovsptd_buffer.o ovsptd_buffer.h
	$(CXX) -Wall -o ovsptd_cmd ovsptd_cmd1.cpp ovsptd_nlmgr.o ovsptd_msgmgr.o ovsptd_buffer.o $(CXXFLAGS)
# cmd2: ovsptd_cmd.cpp ovsptd_nlmgr.o ovsptd_nlmgr.h
# 	$(CXX) -Wall -o ovsptd_cmd ovsptd_cmd.cpp ovsptd_nlmgr.o $(CFLAGS)
# cmd: ovsptd_cmd.c ovsptd_nlmgr.o ovsptd_nlmgr.h
# 	$(CXX) -Wall -o ovsptd_cmd ovsptd_cmd.c ovsptd_nlmgr.o $(CFLAGS)
# release: main.c network.o network.h
# 	$(CC) -Wall -o ovspd main.c network.o $(CFLAGS) -DNDEBUG
# debug: main.c network.o network.h
# 	$(CC) -Wall -o ovspd main.c network.o $(CFLAGS)
# network.o: network.c 
# 	$(CC) -Wall -c network.c
ovsptd_nlmgr.o: ovsptd_nlmgr.c
	$(CXX) -Wall -c ovsptd_nlmgr.c
ovsptd_msgmgr.o: ovsptd_msgmgr.cpp
	$(CXX) -c ovsptd_msgmgr.cpp $(CXXFLAGS)
ovsptd_buffer.o: ovsptd_buffer.cpp
	$(CXX) -c ovsptd_buffer.cpp $(CXXFLAGS)
clean:	
	rm -rf *.o ovspd ovsptd_cmd
dep:
	$(CC) -M *.c > .dep