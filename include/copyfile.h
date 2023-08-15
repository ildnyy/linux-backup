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

void send_file(const char *file_path, int sockfd);
void traverse_directory_and_send_files(const char *dir_path, int sockfd);

#endif