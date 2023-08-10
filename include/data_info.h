#ifndef DATA_INFO_H_
#define DATA_INFO_H_
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/time.h>
#else
#include <sys/types.h>
#include <time.h>
#endif    

#include <stddef.h>

#define PATH_MAX 256
#define MAX_IO_SIZE 4096

enum operation_type {
    OP_READ,
    OP_WRITE,
    OP_CREATE,
    OP_DELETE,
    OP_CREATEDIR,
    OP_DELETEDIR,
};
struct iodata {
    enum operation_type op_type;  // 操作类型
    char path[PATH_MAX];         // 文件路径
    long long offset;            // 写入的偏移量
    size_t length;               // 写入的长度
    unsigned char data[MAX_IO_SIZE];      // 写入的数据   
    struct timespec timestamp;   // 用户空间的时间戳
    uid_t user_id;               // 用户ID
    unsigned int mode;           //权限
};

#endif