#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#define SERVER_IP "0.0.0.0"  // 请替换为你的服务器IP地址
#define SERVER_PORT 8800  // 请选择合适的端口号
#define PATH_MAX 256
#define MAX_PATH 1024
#define MAX_IO_SIZE 4096
int first_backup_done = 0;
volatile sig_atomic_t quit = 0;
fd_set read_fds;
struct timeval tv;
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
    unsigned int mode;           //权限
};
typedef struct {
    char filename[MAX_PATH];
    size_t file_size;
    int is_directory; // 1 if directory, 0 if regular file
} FileHeader;

int replay_io_operation(struct iodata data) {
    int fd;
    ssize_t ret;
    printf("start replay\n");
    switch (data.op_type) {
        case OP_CREATE:
            // 创建文件
            fd = open(data.path, O_CREAT | O_WRONLY, 0755);
            if (fd == -1) {
                perror("Failed to create file\n");
                return 0;
            }
            close(fd);
            break;
        case OP_CREATEDIR: 
            // 创建文件夹
            if (mkdir(data.path, data.mode) == -1) {
                perror("Failed to create directory\n");
                return 0;
            }
            break;
        case OP_WRITE:
            // 写入文件
            fd = open(data.path, O_WRONLY | O_TRUNC);
            if (fd == -1) {
                perror("Failed to open file for writing\n");
                return 0;
            }
            lseek(fd, data.offset, SEEK_SET);
            ret = write(fd, data.data, data.length);
            if (ret == -1) {
                perror("Failed to write file\n");
                return 0;
            }
            close(fd);
            break;
        case OP_DELETE:
            // 删除文件
            ret = remove(data.path);
            if (ret == -1) {
                perror("Failed to delete file\n");
                return 0;
            }
            break;
        case OP_DELETEDIR:
            // 删除文件夹
            ret = rmdir(data.path);
            if (ret == -1) {
                perror("Failed to delete Dir\n");
                return 0;
            }
            break;
        default:
            fprintf(stderr, "Unknown operation type: %d\n", data.op_type);
            return 0; 
    }
    return 1;
}

void rename_dir(const char *old_dir_path) {
    char new_dir_path[PATH_MAX];
    time_t now;
    char time_str[64];
    // Get the current time
    now = time(NULL);
    struct tm *now_tm = localtime(&now);  
    if (now_tm != NULL) {
        int ret = snprintf(time_str, sizeof(time_str), "%04d%02d%02d%02d%02d%02d",
                        now_tm->tm_year + 1900,
                        now_tm->tm_mon + 1,
                        now_tm->tm_mday,
                        now_tm->tm_hour,
                        now_tm->tm_min,
                        now_tm->tm_sec);
        if (ret > 0 && ret < sizeof(time_str)) {
            printf("%s\n", time_str);
        } else {
            fprintf(stderr, "Failed to format time\n");
        }
    } else {
        perror("Failed to get current time");
    }
    snprintf(new_dir_path, sizeof(new_dir_path), "%s_%s", old_dir_path, time_str);
    // Rename the directory
    if (rename(old_dir_path, new_dir_path) != 0) {
        perror("Failed to rename directory");
    }
}

ssize_t recv_all(int socket, void *buffer, size_t length) {
    char *ptr = (char*) buffer;
    ssize_t received = 0;
    while (length > 0) {
        ssize_t r = recv(socket, ptr, length, 0);
        if (r < 1) return received > 0 ? received : r;  
        ptr += r;
        received += r;
        length -= r;
    }
    return received;
}

void ensure_directory_exists(const char *file_path) {
    char *dir_path = strdup(file_path);
    char *sep = strrchr(dir_path, '/');
    if (sep != NULL) {
        *sep = '\0';
        if (strlen(dir_path) > 0) {
            ensure_directory_exists(dir_path);
            mkdir(dir_path, 0755);  // Try to create the directory. It's okay if it already exists.
        }
    }
    free(dir_path);
}

void receive_file(int sockfd, char *backup_path) {
    static int first_receive = 1; 
    FileHeader header;
    FILE *file;
    char buffer[1024];
    size_t bytes_left, bytes_received;
    recv(sockfd, &header, sizeof(FileHeader), 0);

    if (first_receive) {
        // 第一次接收到数据，改变 backup_path 的值
        strncpy(backup_path, header.filename, sizeof(header.filename)); 
        printf("backup_path: %s\n",backup_path);
        first_receive = 0;  
    }

    ensure_directory_exists(header.filename);
    if (strcmp(header.filename, "EOF") == 0) {
        // hole backup complete
        first_backup_done = 1;
        return;
    }
    // If it's a directory, create it
    printf("is_directory, filename %d %s\n",header.is_directory,header.filename);
    if (header.is_directory) {
        mkdir(header.filename, 0755);
    } else {
        // Create and write to the file
        file = fopen(header.filename, "wb");
        if (!file) {
            perror("Failed to create file");
            return;
        }
        bytes_left = header.file_size;
        while (bytes_left > 0) {
            bytes_received = recv(sockfd, buffer, (bytes_left < sizeof(buffer) ? bytes_left : sizeof(buffer)), 0);
            if (bytes_received <= 0) {
                perror("Failed to receive file data");
                break;
            }
            fwrite(buffer, 1, bytes_received, file);
            bytes_left -= bytes_received;
        }
        fclose(file);
    }
}

void signal_handler(int sig) {
    printf("Received SIGINT, setting quit to 1.\n");
    quit = 1;
}

int main() {
    int listen_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct iodata data;
    ssize_t ret;
    char backup_path[MAX_PATH];
    char backup_dir_path[MAX_PATH];

    signal(SIGINT, signal_handler);
    // 创建监听套接字
    listen_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_sock == -1) {
        perror("Failed to create socket");
        return -1;
    }

    // 设置服务器地址结构体
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // 绑定套接字
    if (bind(listen_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Failed to bind socket");
        close(listen_sock);
        return -1;
    }

    // 开始监听连接请求
    if (listen(listen_sock, 5) == -1) {  // 最多允许5个待处理的连接
        perror("Failed to listen on socket");
        close(listen_sock);
        return -1;
    }

    printf("Server is listening on %s:%d...\n", SERVER_IP, SERVER_PORT);

    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_sock == -1) {
        perror("Failed to accept client connection");
    }

    printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));

    while (1) {
        receive_file(client_sock, backup_path);
        if (first_backup_done){
            printf("全备完成");
            break;
        }
    }
    close(client_sock);

    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_sock == -1) {
        perror("Failed to accept client connection");
    }

    printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    while (!quit && first_backup_done) {
        // 从客户端接收数据
        FD_ZERO(&read_fds);
        FD_SET(client_sock, &read_fds);
        tv.tv_sec = 1;  // timeout after 1 second
        tv.tv_usec = 0;
        int activity = select(client_sock + 1, &read_fds, NULL, NULL, &tv);

        if (quit) {
            break;
        }
        if (activity < 0) {
            perror("select error");
        } else if (activity == 0) {
            // timeout, no data available
            continue;
        } else {
            if (FD_ISSET(client_sock, &read_fds)) {
                // 从客户端接收数据
                ssize_t received_bytes = recv_all(client_sock, &data, sizeof(data));
                if (received_bytes == sizeof(data)) {
                    printf("receiving...\n");
                    // 处理接收到的数据
                    int flag = replay_io_operation(data);
                    if(flag){
                        printf("replay success!\n");
                    }
                    else{
                        printf("replay fail.\n");
                    }
                }
                else if (received_bytes == -1) {
                    perror("Error receiving data.\n");
                }
            }
        }
    }
    close(client_sock);
    close(listen_sock);
    printf("%s\n",backup_path);
    rename_dir(backup_path);
    return 0;
}
