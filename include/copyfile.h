#ifndef COPYFILE_H
#define COPYFILE_H
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include "data_info.h"

typedef struct {
    char filename[PATH_MAX];
    size_t file_size;
    int is_directory; // 1 if directory, 0 if regular file
} FileHeader;

void send_file(const char *file_path, int sockfd);
void traverse_directory_and_send_files(const char *dir_path, int sockfd);

#endif