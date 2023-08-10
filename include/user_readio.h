#ifndef USER_READIO_H
#define USER_READIO_H
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "data_info.h"

#define SERVER_IP "172.18.44.10"  // 请替换为你的服务器IP地址
#define SERVER_PORT 8800  // 请选择合适的端口号
int sockfd;

int connect_to_server();
int send_data_to_server(struct iodata data);
#endif
