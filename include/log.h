#ifndef LOG_H
#define LOG_H

#include <stdio.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include "data_info.h"

void write_log(struct iodata data, char *backup_path);
int read_log(FILE *log_file, struct iodata* data);
int copy_file(const char *source_path, const char *destination_path);
int copy_item(const char *source_path, const char *destination_path);
int copy_directory(const char *source_path, const char *destination_path);
#endif