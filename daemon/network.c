#include "network.h"

#define proc_error(x) \
    do \
    { \
        perror(#x); \
        return -1; \
    }while(0)
/*
int get_listen_sock(unsigned short port)
{
    struct sockaddr_in sockIn;
    int sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
        proc_error("call to socket");
    
    int on = 1;
    int status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    if (status == -1)
        proc_error("call to setsockopt");
    
    bzero(&sockIn, sizeof(sockIn));
    sockIn.sin_family = AF_INET;
    sockIn.sin_addr.s_addr = htonl(INADDR_ANY);
    sockIn.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&sockIn, sizeof(sockIn)) == -1)
        proc_error("call to bind");
    
    if (listen(sockfd, 20) == -1)
        proc_error("call to listen");
    
    return sockfd;
}
*/
int get_listen_sock(unsigned long int address, unsigned short port)
{
    struct sockaddr_in sockIn;
    int sockfd = socket (AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
        proc_error("call to socket");
    
    int on = 1;
    int status = setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (const char *)&on, sizeof(on));
    if (status == -1)
        proc_error("call to setsockopt");
    
    bzero(&sockIn, sizeof(sockIn));
    sockIn.sin_family = AF_INET;
    sockIn.sin_addr.s_addr = address;
    sockIn.sin_port = htons(port);

    if (bind(sockfd, (struct sockaddr *)&sockIn, sizeof(sockIn)) == -1)
        proc_error("call to bind");
    
    if (listen(sockfd, 20) == -1)
        proc_error("call to listen");
    
    return sockfd;
}

int connect_to(char address[], unsigned short port)
{
    int sockfd = socket(AF_INET , SOCK_STREAM , 0);
    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(address);
    server.sin_family = AF_INET;
    server.sin_port = htons( port );
    
    if (connect(sockfd , (struct sockaddr *)&server , sizeof(server)) < 0)
        proc_error("call to connect");
    
    return sockfd;
}
/*
int connect_to(unsigned long int address, unsigned short port)
{
    int sockfd = socket(AF_INET , SOCK_STREAM , 0);
    struct sockaddr_in server;
    server.sin_addr.s_addr = address;
    server.sin_family = AF_INET;
    server.sin_port = htons( port );
    
    if (connect(sockfd , (struct sockaddr *)&server , sizeof(server)) < 0)
        proc_error("call to connect");

    return sockfd;
}
*/
