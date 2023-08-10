#ifndef READ_CFG_H
#define READ_CFG_H
#define TARGET_KEY "target_path"
#include <stdio.h>
#include <string.h>
#include "data_info.h"
int read_config(const char* config_filename, struct tm* deadline);
int read_path(const char *config_file_path, char *out_target_path, size_t len);

#endif