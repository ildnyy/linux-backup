#include "user_readio.h"
#include "copyfile.h"
#include "read_cfg.h"

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

int main(int argc, char *argv[]) {
    // struct iodata data;
    // ssize_t ret;
    FileHeader end_of_transfer;
    char backup_dir_path[PATH_MAX];
    if (connect_to_server() == -1) {
        return -1;
    }

    // if (argc < 2) {
    //     printf("Please provide the backup directory path as a command line argument.\n");
    //     return -1;
    // }
    
    /*备份目标路径 */
    // strncpy(backup_dir_path, argv[1], sizeof(backup_dir_path) - 1);
    // backup_dir_path[sizeof(backup_dir_path) - 1] = '\0';

    read_path("../config.txt",backup_dir_path,sizeof(backup_dir_path));

    send_file(backup_dir_path,sockfd);
    traverse_directory_and_send_files(backup_dir_path, sockfd);
    memset(&end_of_transfer, 0, sizeof(end_of_transfer)); 
    strcpy(end_of_transfer.filename, "EOF");
    send(sockfd, &end_of_transfer, sizeof(end_of_transfer), 0);

    /* 使用read系统调用从内核模块中读取数据(速度慢) 
    int fd = open("/proc/iodata", O_RDONLY);
    while (1) {
        ret = read(fd, &data, sizeof(data));
        if (ret < sizeof(data)) {
            sleep(1);
            continue;
        }
        send_data_to_server(data);  // 发送数据到服务器

        printf("Operation type: %d\n", data.op_type);
        printf("File path is: %s\n", data.path);
        printf("Data: %s\n", data.data);
        printf("uid: %u\n", data.user_id);
    }
    close(fd);
    */  
    close(sockfd);
    
    return 0;
}
