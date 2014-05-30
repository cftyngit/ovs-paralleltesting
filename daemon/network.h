#ifndef NETWORK_H
#define NETWORK_H

#include <stdio.h> /*perror*/
#include <string.h> /*bzero*/

#include <sys/types.h>          /* See NOTES */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define LISTEN_BACKLOG 20

//int get_listen_sock(unsigned short port);
int get_listen_sock(unsigned long int address, unsigned short port);
int connect_to(char address[], unsigned short port);
//int connect_to(unsigned long int address, unsigned short port);

#endif // NETWORK_H
