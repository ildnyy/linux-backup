#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

// 假设路径的最大长度
#define MAX_PATH 1024
typedef struct {
    char filename[MAX_PATH];
    size_t file_size;
    int is_directory; // 1 if directory, 0 if regular file
} FileHeader;

void send_file(const char *file_path, int sockfd);
void traverse_directory_and_send_files(const char *dir_path, int sockfd);
void create_backup_directory(const char *dir_path, char *backup_dir_path, size_t len);