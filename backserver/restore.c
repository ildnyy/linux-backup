#include "restore.h"

int restore(const char* log_filename, const char* config_filename) {
    struct iodata data;
    struct tm deadline;
    struct timespec timestamp_now, timestamp_deadline;
    int ret;

    FILE* log_file = fopen(log_filename, "r");
    if (log_file == NULL) {
        perror("Error opening log file.\n");
        return -1;
    }
    // 以时间为截点进行恢复
    while (1) {
        ret = read_log(log_filename, &data);
        if (ret == 0) {
            clock_gettime(CLOCK_REALTIME, &data.timestamp);
            data.timestamp.tv_sec += 8 * 3600; // 加上8个小时的偏移
            timestamp_now = data.timestamp; 
            read_config("../config.txt", &deadline);

            timestamp_deadline.tv_sec = mktime(&deadline);
            timestamp_deadline.tv_nsec = 0;

            if (timestamp_now.tv_sec < timestamp_deadline.tv_sec ||
               (timestamp_now.tv_sec == timestamp_deadline.tv_sec && timestamp_now.tv_nsec <= timestamp_deadline.tv_nsec)) {
                replay_io_operation(data);
            } else {
                break; // 超过截止时间，退出循环
            }
        }
    }
    fclose(log_file);
    return 0;
}
//恢复
int main(){
    
    restore("../log_file.txt", "../config.txt");
    
    return 0;
}