#ifndef IODATA_H
#define IODATA_H

#include <linux/types.h>
#include <linux/time.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/splice.h>
#include <linux/namei.h>
#include <linux/fdtable.h>
#include <linux/fs_struct.h>
#include <linux/net.h>
#include <linux/moduleparam.h>
#include <net/sock.h>
#include <linux/inet.h>
#include "data_info.h"

static char path_buffer[PATH_MAX];
static char *target_path = "/home/ildnyy/test"; //默认路径
static size_t target_path_len;
static struct mutex path_mutex;
static DEFINE_MUTEX(list_mutex);
static LIST_HEAD(iodata_list);
static struct socket *sock;

module_param(target_path, charp, 0644);
MODULE_PARM_DESC(target_path, "Target path to monitor");

// #define PATH_MAX 256
// #define MAX_IO_SIZE 4096

// enum operation_type {
//     OP_READ,
//     OP_WRITE,
//     OP_CREATE,
//     OP_DELETE,
//     OP_CREATEDIR,
//     OP_DELETEDIR,
// };
// struct iodata {
//     enum operation_type op_type;  // 操作类型
//     char path[PATH_MAX];         // 文件路径
//     long long offset;            // 写入的偏移量
//     size_t length;               // 写入的长度
//     unsigned char data[MAX_IO_SIZE];      // 写入的数据   
//     struct timespec timestamp;   // 时间戳
//     uid_t user_id;               // 用户ID
//     unsigned int mode;           //权限
// };

struct iodata_node {
    struct iodata data;
    struct list_head list;
};

int k_vfs_write(struct kprobe *p, struct pt_regs *regs);
int k_do_sys_open(struct kprobe *p, struct pt_regs *regs);
int k_vfs_unlink(struct kprobe *p, struct pt_regs *regs);
int k_do_mkdirat(struct kprobe *p, struct pt_regs *regs);
static ssize_t iodata_read(struct file *file, char __user *buf, size_t len, loff_t *offset);
char *get_absolute_path_from_dfd_pid(int dfd, pid_t pid, const char __user *pathname_user);
struct iodata_node *create_and_addnode(const char *pathname, enum operation_type op_type, loff_t offset, size_t length, const unsigned char *data, uid_t user_id, umode_t mode);
static int __init our_init(void);
static void __exit our_exit(void);

static const struct file_operations proc_fops = {
    .read = iodata_read,
};
#endif
