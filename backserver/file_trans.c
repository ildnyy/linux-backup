#include "file_trans.h"

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
    printf("is_directory:%d, filename:%s\n",header.is_directory,header.filename);
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
