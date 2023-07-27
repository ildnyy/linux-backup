// iodata.h
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

#define PATH_MAX 256
#define MAX_IO_SIZE 4096

static char path_buffer[PATH_MAX];
static char path_buffer1[PATH_MAX];
enum operation_type {
    OP_READ,
    OP_WRITE,
    OP_CREATE,
    OP_DELETE,
};

struct iodata {
    enum operation_type op_type;  // 操作类型
    char path[PATH_MAX];         // 文件路径
    loff_t offset;               // 写入的偏移量
    size_t length;               // 写入的长度
    unsigned char data[MAX_IO_SIZE];      // 写入的数据
    struct timespec timestamp;   // 时间戳
    uid_t user_id;               // 用户ID
};

struct iodata_node {
    struct iodata data;
    struct list_head list;
};

int k_vfs_write(struct kprobe *p, struct pt_regs *regs);
int k_do_sys_open(struct kprobe *p, struct pt_regs *regs);
int k_vfs_unlink(struct kprobe *p, struct pt_regs *regs);
static ssize_t iodata_read(struct file *file, char __user *buf, size_t len, loff_t *offset);
char *get_absolute_path_from_user(const char __user *pathname_user);
static int __init our_init(void);
static void __exit our_exit(void);

#endif


/*struct kprobe {
    struct hlist_node hlist;-----------------------------------------------被用于kprobe全局hash，索引值为被探测点的地址。
    struct list_head list;-------------------------------------------------用于链接同一被探测点的不同探测kprobe。
    unsigned long nmissed;
    kprobe_opcode_t *addr;-------------------------------------------------被探测点的地址。
    const char *symbol_name;-----------------------------------------------被探测函数的名称。
    unsigned int offset;---------------------------------------------------被探测点在函数内部的偏移，用于探测函数内核的指令，如果该值为0表示函数的入口。
    kprobe_pre_handler_t pre_handler;--------------------------------------被探测点指令执行之前调用的回调函数。
    kprobe_post_handler_t post_handler;------------------------------------被探测点指令执行之后调用的回调函数。
    kprobe_fault_handler_t fault_handler;----------------------------------在执行pre_handler、post_handler或单步执行被探测指令时出现内存异常则会调用该回调函数。
    kprobe_break_handler_t break_handler;----------------------------------在执行某一kprobe过程中出发了断点指令后会调用该函数，用于实现jprobe。
    kprobe_opcode_t opcode;------------------------------------------------保存的被探测点原始指令。
    struct arch_specific_insn ainsn;---------------------------------------被复制的被探测点的原始指令，用于单步执行，架构强相关。
    u32 flags;-------------------------------------------------------------状态标记。
}; */
