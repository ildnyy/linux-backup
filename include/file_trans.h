#ifndef FILE_TRANS_H
#define FILE_TRANS_H

#include <string.h>
#include <stdio.h>
#include "data_info.h"

extern int first_backup_done;
void ensure_directory_exists(const char *file_path);
void receive_file(int sockfd, char *backup_path);

#endif