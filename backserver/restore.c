#include "restore.h"
#include "log.h"
#include "read_cfg.h"
#include "copyfile.h"

int replay_io_operation(struct iodata data) {
    ssize_t ret;
    FILE *file;
    size_t written;
    printf("start replay\n");
    switch (data.op_type) {
        case OP_CREATE:
            // 创建文件
           file = fopen(data.path, "w");
            if (file == NULL) {
                perror("Failed to create file\n");
                return 0;
            }
            fclose(file);
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
            file = fopen(data.path, "r+b"); // 以读/写模式打开，不截断文件
            if (file == NULL) {
                perror("Failed to open file for writing\n");
                return 0;
            }
            printf("offset: %lld\n", data.offset);
            if (fseek(file, data.offset, SEEK_SET) == -1){
                perror("Failed to seek file\n");
                fclose(file);
                return 0;
            }
            written = fwrite(data.data, 1, data.length, file);
            if (written != data.length) {
                perror("Failed to write file\n");
                fclose(file);
                return 0;
            }
            fclose(file);
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
            ret = remove_directory(data.path);
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

int remove_directory(const char *path) {
    DIR *d = opendir(path);
    size_t path_len = strlen(path);
    int r = -1;

    if (d) {
        struct dirent *p;
        r = 0;
        while (!r && (p = readdir(d))) {
            int r2 = -1;
            char *buf;
            size_t len;

            if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
                continue;
            }

            len = path_len + strlen(p->d_name) + 2;
            buf = malloc(len);

            if (buf) {
                struct stat statbuf;
                snprintf(buf, len, "%s/%s", path, p->d_name);

                if (!stat(buf, &statbuf)) {
                    if (S_ISDIR(statbuf.st_mode)) {
                        r2 = remove_directory(buf);
                    } else {
                        r2 = unlink(buf);
                    }
                }

                free(buf);
            }

            r = r2;
        }
        closedir(d);
    }

    if (!r) {
        r = rmdir(path);
    }

    return r;
}

int restore(const char* log_filename, const char* config_filename) {
    struct tm deadline;
    struct timespec timestamp_now, timestamp_deadline;
    int ret;
    struct iodata data;
    FILE* log_file = fopen(log_filename, "r");
    if (log_file == NULL) {
        perror("Error opening log file.\n");
        return -1;
    }
    // 以时间为截点进行恢复
    while(!feof(log_file)) {
        ret = read_log(log_file, &data);
        if (ret == 0) {
            clock_gettime(CLOCK_REALTIME, &data.timestamp);
            data.timestamp.tv_sec += 8 * 3600; // 加上8个小时的偏移
            timestamp_now = data.timestamp; 
            read_config("../config.txt", &deadline);
            timestamp_deadline.tv_sec = mktime(&deadline);
            timestamp_deadline.tv_nsec = 0;
            
            if (timestamp_now.tv_sec < timestamp_deadline.tv_sec ||
               (timestamp_now.tv_sec == timestamp_deadline.tv_sec && timestamp_now.tv_nsec <= timestamp_deadline.tv_nsec)) {
                replay_io_operation(data);
            } else {
                printf("time out\n");
                break; // 超过截止时间，退出循环
            }
        }
    }
    fclose(log_file);
    return 0;
}
//恢复
int main(){
    int sockfd;
    struct sockaddr_in server_addr;
    char server_ip[16];  // 假设使用 IPv4 地址格式
    unsigned int server_port;
    char backup_dir_path[PATH_MAX];
    FileHeader end_of_transfer;

    restore("./log_file.txt", "../config.txt");
    // 创建套接字
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("Failed to create socket");
        return -1;
    }

    read_backup_server_info("../config.txt", server_ip, &server_port,"HOST_SERVER");
    // 设置服务器地址结构体
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(server_port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);

    // 连接到服务器
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Failed to connect to server");
        close(sockfd);
        return 0;
    }

    //传输
    read_path("../config.txt",backup_dir_path,sizeof(backup_dir_path));
    strcat(backup_dir_path, "_copy");

    send_file(backup_dir_path, sockfd); 
    traverse_directory_and_send_files(backup_dir_path, sockfd);
    memset(&end_of_transfer, 0, sizeof(end_of_transfer)); 
    strcpy(end_of_transfer.filename, "EOF");
    send(sockfd, &end_of_transfer, sizeof(end_of_transfer), 0);

    close(sockfd);
    printf("传输完成！\n");

    return 0;
}