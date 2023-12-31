#include "read_cfg.h"

int read_config(const char* config_filename, struct tm* deadline) {
    FILE* config_file = fopen(config_filename, "r");
    if (config_file == NULL) {
        perror("Error opening config file.\n");
        return -1;
    }

    if (fscanf(config_file, "Year: %d Month: %d Day: %d Hour: %d Minute: %d Second: %d\n",
               &deadline->tm_year, &deadline->tm_mon, &deadline->tm_mday,
               &deadline->tm_hour, &deadline->tm_min, &deadline->tm_sec) != 6) {
        fprintf(stderr, "Error reading config file.\n");
        return -1;
    }

    deadline->tm_year -= 1900; // tm_year是从1900年开始计数的
    deadline->tm_mon -= 1;     // tm_mon的范围是0-11

    fclose(config_file);
    return 0;
}

int read_path(const char *config_file_path, char *out_target_path, size_t len) {
    FILE *file = fopen(config_file_path, "r");
    if (file == NULL) {
        fprintf(stderr, "Failed to open config file: %s\n", config_file_path);
        return -1;
    }
    char line[256];
    while (fgets(line, sizeof(line), file)) {
        // 查找 target_path 行
        if (strncmp(line, TARGET_KEY, strlen(TARGET_KEY)) == 0) {
            // 从找到的行中提取路径
            sscanf(line, TARGET_KEY ": \"%255[^\"]\"", out_target_path);
            break;
        }
    }

    fclose(file);

    return 0;
}