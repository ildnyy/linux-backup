#include "log.h"

void write_log(struct iodata data)
{
    // 打开日志文件
    FILE* log_file = fopen("log_file.txt", "a");
    if (log_file != NULL) {
        // 写入时间戳和其他字段（在同一行）
        strcat(data.path, "_copy");
        fprintf(log_file, "Timestamp: %ld.%ld Operation Type: %d Path: %s Offset: %lld Length: %zu User ID: %d Mode: %u\nData: ",
                data.timestamp.tv_sec, data.timestamp.tv_nsec, data.op_type, data.path, data.offset, data.length, data.user_id, data.mode);

        // 写入数据
        for(size_t i = 0; i < data.length; i++) {
            fprintf(log_file, "%02x ", data.data[i]);
        }

        fprintf(log_file, "\n\n"); // 两个换行符以便于阅读
        fclose(log_file);
    }
}; 

int read_log(FILE *log_file, struct iodata* data) {
    if (log_file == NULL) {
        perror("Error opening log file.\n");
        return -1;
    }

    // 读取时间戳和其他字段（从同一行）
    if (fscanf(log_file, "Timestamp: %ld.%ld Operation Type: %d Path: %s Offset: %lld Length: %zu User ID: %d Mode: %u\n",
               &data->timestamp.tv_sec, &data->timestamp.tv_nsec, (int*)&data->op_type, data->path, &data->offset, &data->length, &data->user_id, &data->mode) != 8) {
        fprintf(stderr, "Error reading log line.\n");
        return -1;
    }

    // 读取数据 
    for(size_t i = 0; i < data->length; i++) {
        unsigned int byte;
        if (fscanf(log_file, "%02x ", &byte) != 1) {
            fprintf(stderr, "Error reading data.\n");
            return -1;
        }
        data->data[i] = byte;
    }
    return 0;
}

int copy_file(const char *source_path, const char *destination_path) {
    FILE *source_file = fopen(source_path, "rb");
    if (source_file == NULL) {
        perror("Error opening source file");
        return -1;
    }

    FILE *destination_file = fopen(destination_path, "wb");
    if (destination_file == NULL) {
        perror("Error opening destination file");
        fclose(source_file);
        return -1;
    }

    char buffer[1024];
    size_t bytes_read, bytes_written;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), source_file)) > 0) {
        bytes_written = fwrite(buffer, 1, bytes_read, destination_file);
        if (bytes_written != bytes_read) {
            fprintf(stderr, "Error writing to destination file\n");
            fclose(source_file);
            fclose(destination_file);
            return -1;
        }
    }

    fclose(source_file);
    fclose(destination_file);
    return 0;
}

int copy_item(const char *source_path, const char *destination_path) {
    struct stat info;
    if (stat(source_path, &info) != 0) {
        perror("Error reading source item");
        return -1;
    }

    if (S_ISDIR(info.st_mode)) {
        return copy_directory(source_path, destination_path);
    } else {
        return copy_file(source_path, destination_path);
    }
}

int copy_directory(const char *source_path, const char *destination_path) {
    mkdir(destination_path, 0777);
    DIR *dir = opendir(source_path);
    if (dir == NULL) {
        perror("Error opening source directory");
        return -1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char source_item_path[1024];
        char destination_item_path[1024];

        snprintf(source_item_path, sizeof(source_item_path), "%s/%s", source_path, entry->d_name);
        snprintf(destination_item_path, sizeof(destination_item_path), "%s/%s", destination_path, entry->d_name);

        if (copy_item(source_item_path, destination_item_path) != 0) {
            closedir(dir);
            return -1;
        }
    }

    closedir(dir);
    return 0;
}
