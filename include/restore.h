#ifndef RESTORE_H
#define RESTORE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include "data_info.h"

int restore(const char* log_filename, const char* config_filename);

#endif