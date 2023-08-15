#include "user_readio.h"
#include "copyfile.h"
#include "read_cfg.h"
#include "file_trans.h"

int connect_to_server() {
    struct sockaddr_in server_addr;

    // 创建套接字
    printf("connect to server...\n");
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Failed to create socket");
        return -1;
    }

    // 设置服务器地址结构体
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = inet_addr(SERVER_IP);

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Failed to connect to server");
        close(sockfd);
        return -1;
    }

    return 0;
}

int send_data_to_server(struct iodata data) {
    // 发送数据
    ssize_t sent_bytes = send(sockfd, &data, sizeof(data), 0);
    if (sent_bytes != sizeof(data)) {
        perror("Failed to send data");
        return -1;
    }

    return 0;
}

void handle_signal(int signal) {
    quit = 1;
}

int main(int argc, char *argv[]) {
    FileHeader end_of_transfer;
    char backup_dir_path[PATH_MAX];
    if (connect_to_server() == -1) {
        return -1;
    }

    read_path("../config.txt",backup_dir_path,sizeof(backup_dir_path));

    send_file(backup_dir_path,sockfd);
    traverse_directory_and_send_files(backup_dir_path, sockfd);
    memset(&end_of_transfer, 0, sizeof(end_of_transfer)); 
    strcpy(end_of_transfer.filename, "EOF");
    send(sockfd, &end_of_transfer, sizeof(end_of_transfer), 0);
    close(sockfd);

    // 新增部分：在8800端口等待服务器连接
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sa.sa_flags = 0; // 使用默认属性
    sigemptyset(&sa.sa_mask); // 清空信号集
    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        return -1;
    }
    int server_sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sockfd < 0) {
        perror("socket");
        return -1;
    }

    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = htonl(INADDR_ANY);
    server_address.sin_port = htons(8800); // 端口号8800

    if (bind(server_sockfd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("bind");
        return -1;
    }

    if (listen(server_sockfd, 5) < 0) { // 最大允许5个待处理连接
        perror("listen");
        return -1;
    }

    struct sockaddr_in client_address;
    socklen_t addrlen = sizeof(client_address);
    int new_sockfd = accept(server_sockfd, (struct sockaddr*)&client_address, &addrlen);
    if (new_sockfd < 0) {
        perror("accept");
        return -1;
    }
    
    while (!quit) { // 无限循环，等待下一次恢复的socket连接，直到Ctrl+C被按下
        struct sockaddr_in client_address;
        socklen_t addrlen = sizeof(client_address);
        int new_sockfd = accept(server_sockfd, (struct sockaddr*)&client_address, &addrlen);
        if (new_sockfd < 0) {
            perror("accept");
            continue; // 如果accept失败，则继续等待下一个连接
        }
        printf("Accepted connection from %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));
        // 接收数据
        while (!quit) {
            receive_file(new_sockfd, backup_dir_path);
            if (first_backup_done){
                printf("恢复完成！\n");
                break;
            }
        }
        close(new_sockfd); // 关闭当前连接，准备接受下一个连接
    }
    close(server_sockfd);
    
    return 0;
}
