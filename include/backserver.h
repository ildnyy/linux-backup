#ifndef BACKSERVER_H
#define BACKSERVER_H
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include "data_info.h"

#define SERVER_IP "0.0.0.0" 
#define SERVER_PORT 8800 
int first_backup_done = 0;
volatile sig_atomic_t quit = 0;
fd_set read_fds;
struct timeval tv;

typedef struct {
    char filename[PATH_MAX];
    size_t file_size;
    int is_directory; // 1 if directory, 0 if regular file
} FileHeader;

int replay_io_operation(struct iodata data);
int remove_directory(const char *path);
void rename_dir(const char *old_dir_path);
ssize_t recv_all(int socket, void *buffer, size_t length);
void ensure_directory_exists(const char *file_path);
void receive_file(int sockfd, char *backup_path);
void signal_handler(int sig);
#endif
