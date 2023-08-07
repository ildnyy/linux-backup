#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define PATH_MAX 256
#define MAX_IO_SIZE 4096
#define SERVER_IP "172.18.44.10"  // 请替换为你的服务器IP地址
#define SERVER_PORT 8800  // 请选择合适的端口号
int sockfd;

enum operation_type {
    OP_READ,
    OP_WRITE,
    OP_CREATE,
    OP_DELETE,
    OP_CREATEDIR,
    OP_DELETEDIR,
};

struct iodata {
    enum operation_type op_type;  // 操作类型
    char path[PATH_MAX];         // 文件路径
    long long offset;            // 写入的偏移量
    size_t length;               // 写入的长度
    unsigned char data[MAX_IO_SIZE];      // 写入的数据
    struct timespec timestamp;   // 时间戳
    uid_t user_id;               // 用户ID
};

int connect_to_server();
int send_data_to_server(struct iodata data);
