#include "copyfile.h"

void send_file(const char *file_path, int sockfd) {
    FILE *file;
    FileHeader header;
    size_t bytes_read;
    char buffer[1024];

    // Fill the header information
    strncpy(header.filename, file_path, PATH_MAX);

    struct stat st;
    stat(file_path, &st);
    header.file_size = st.st_size;
    header.is_directory = S_ISDIR(st.st_mode);

    // Send the header first
    send(sockfd, &header, sizeof(FileHeader), 0);
    printf("size: %ld\n",header.file_size);
    // If it's a regular file, send its content
    if (!header.is_directory) {
        file = fopen(file_path, "rb");
        if (!file) {
            perror("Failed to open file");
            return;
        }
        while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0) {
            send(sockfd, buffer, bytes_read, 0);
        }
        fclose(file);
    }
}

void traverse_directory_and_send_files(const char *dir_path, int sockfd) {
    DIR *dir;
    struct dirent *entry;
    char path[1024];
    struct stat info;

    // Open the directory
    dir = opendir(dir_path);
    if (dir == NULL) {
        perror("Failed to open directory");
        return;
    }
    // Traverse each entry in the directory
    while ((entry = readdir(dir)) != NULL) {
        // Ignore "." and ".." entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || strstr(entry->d_name, ".swp") != NULL) {
            continue;
        }
        // Construct the full path of the entry
        snprintf(path, sizeof(path), "%s/%s", dir_path, entry->d_name);
        printf("fullpath: %s\n",path);
        // Get the information of the entry
        if (stat(path, &info) == -1) {
            perror("Failed to get file info");
            continue;
        }
        // If it's a directory, send the directory info and recursively traverse it
        if (S_ISDIR(info.st_mode)) {
            send_file(path,sockfd);
            traverse_directory_and_send_files(path, sockfd);
        }
        // If it's a file, send it to the server
        else if (S_ISREG(info.st_mode)) {
            send_file(path, sockfd);
        }
    }
    closedir(dir);
    return;
}
