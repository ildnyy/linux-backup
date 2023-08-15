#include "backserver.h"
#include "log.h"
#include "file_trans.h"

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

void signal_handler(int sig) {
    printf("Received SIGINT, setting quit to 1.\n");
    quit = 1;
}

int main() {
    int listen_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    struct iodata data;
    char backup_path[PATH_MAX];

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
    if (listen(listen_sock, 5) == -1) { 
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
            printf("全备完成\n");
            char backup_copy_path[PATH_MAX];
            strcpy(backup_copy_path, backup_path);
            strcat(backup_copy_path, "_copy");
            if (copy_item(backup_path, backup_copy_path) == 0) {
                printf("副本保存成功\n");
            } else {
                printf("副本保存失败\n");
            }
            break;
        }
    }
    close(client_sock);

    client_sock = accept(listen_sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client_sock == -1) {
        perror("Failed to accept client connection");
    }

    printf("Accepted connection from %s:%d\n", inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
    //实时接收数据
    while (!quit && first_backup_done) {
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
            continue;
        } else {
            if (FD_ISSET(client_sock, &read_fds)) {
                // 从客户端接收数据
                ssize_t received_bytes = recv_all(client_sock, &data, sizeof(data));
                if (received_bytes == sizeof(data)) {
                    write_log(data, backup_path);
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
    rename_dir(backup_path);
    return 0;
}
