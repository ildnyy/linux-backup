#include "pro_stopio.h"

static ssize_t iodata_read(struct file *file, char __user *buf, size_t len, loff_t *offset)
{
    struct iodata_node *node;
    ssize_t ret = 0;

    mutex_lock(&list_mutex);

    if (list_empty(&iodata_list))
    {
        ret = 0;
        goto out;
    }

    node = list_first_entry(&iodata_list, struct iodata_node, list);

    if (len < sizeof(struct iodata))
    {
        ret = -EINVAL;
        goto out;
    }

    if (copy_to_user(buf, &node->data, sizeof(struct iodata)))
    {
        ret = -EFAULT;
        goto out;
    }

    list_del(&node->list);
    kfree(node);

    ret = sizeof(struct iodata);

out:
    mutex_unlock(&list_mutex);
    return ret;
}

char *get_absolute_path_from_dfd_pid(int dfd, pid_t pid, const char __user *pathname_user)
{
    struct file *file;
    struct path path;
    char *pathname_kernel;
    char *abs_path = NULL;

    rcu_read_lock();

    if (dfd == AT_FDCWD) {
        path = current->fs->pwd;  // Get the working directory of the current process
    } else {
        struct fdtable *fdt;
        struct task_struct *task;

        task = pid_task(find_vpid(pid), PIDTYPE_PID);
        if (task) {
            fdt = files_fdtable(task->files);
            file = fdt->fd[dfd];  // Get the file* associated with the dfd
            if (file) {
                path = file->f_path;  // Get the path struct from the file struct
            } else {
                rcu_read_unlock();
                return NULL;
            }
        } else {
            rcu_read_unlock();
            return NULL;
        }
    }

    pathname_kernel = d_path(&path, path_buffer, PATH_MAX);
    if (IS_ERR(pathname_kernel)) {
        pathname_kernel = NULL;
    } else {
        // Concatenate the directory path with the filename
        strlcat(pathname_kernel, "/", PATH_MAX);
        strlcat(pathname_kernel, pathname_user, PATH_MAX);
        abs_path = kstrdup(pathname_kernel, GFP_KERNEL);
    }

    rcu_read_unlock();

    return abs_path;
}

struct iodata_node *create_and_addnode(const char *pathname, enum operation_type op_type, loff_t offset, size_t length, const unsigned char *data, uid_t user_id, umode_t mode) 
{
    size_t data_offset = 0;
    //其他不需要数据的情况
    if(op_type != OP_WRITE){
        struct iodata_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        struct msghdr msg;
        struct kvec vec;
        int ret;
        if (!new_node) {
            printk(KERN_ERR "Failed to allocate memory for new iodata node.\n");
            return NULL;
        }

        new_node->data.op_type = op_type;
        strncpy(new_node->data.path, pathname, PATH_MAX);
        new_node->data.offset = 0;
        new_node->data.length = 0;
        memset(new_node->data.data, 0, MAX_IO_SIZE); // 或根据需要设置其他字段

        ktime_get_ts(&new_node->data.timestamp);
        new_node->data.user_id = user_id;
        new_node->data.mode = mode;

        memset(&msg, 0, sizeof(msg)); 
        vec.iov_base = &new_node->data;
        vec.iov_len = sizeof(new_node->data);
        msg.msg_flags = MSG_DONTWAIT;  // non-blocking operation

        ret = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);
        if (ret < 0) {
            printk(KERN_ERR "Failed to send message, error %d\n", ret);
        }

        kfree(new_node);
        return NULL;
    }
    //分段发送数据
    while (data_offset < length && op_type == OP_WRITE) {
        struct iodata_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        int ret;
        size_t segment_length;
        struct msghdr msg;
        struct kvec vec;
        if (!new_node) {
            printk(KERN_ERR "Failed to allocate memory for new iodata node.\n");
            return NULL;
        }
        new_node->data.op_type = op_type;
        strncpy(new_node->data.path, pathname, PATH_MAX);
        new_node->data.offset = offset + data_offset;
        // 分割数据，确保在UTF-8字符边界上分割
        segment_length = min(length - data_offset, (size_t)MAX_IO_SIZE);
        if (segment_length == 0) {
            printk(KERN_ERR "Segment length is zero, possibly due to small MAX_IO_SIZE.\n");
            // 处理错误，例如通过返回错误代码
        }
        while (segment_length > 1 && (data[data_offset + segment_length - 1] & 0xC0) == 0x80) {
            segment_length--;
        }
        new_node->data.length = segment_length;
        memcpy(new_node->data.data, data + data_offset, segment_length);

        ktime_get_ts(&new_node->data.timestamp);
        new_node->data.user_id = user_id;
        new_node->data.mode = mode;

        memset(&msg, 0, sizeof(msg));
        // Prepare the message
        vec.iov_base = &new_node->data;
        vec.iov_len = sizeof(new_node->data);
        msg.msg_flags = MSG_DONTWAIT;  // non-blocking operation

        // Send the message
        ret = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);
        if (ret < 0) {
            printk(KERN_ERR "Failed to send message, error %d\n", ret);
        }

        data_offset += segment_length;

        // Deallocate the memory for the node after sending it
        kfree(new_node);
    }

    return NULL;
}

int k_vfs_write(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file = (struct file *)regs->di; 
    char *data = (char *)regs->si;
    char *pathname;
    int pathname_len;

    mutex_lock(&path_mutex);
    pathname = d_path(&file->f_path, path_buffer, PATH_MAX);

    if (IS_ERR(pathname))
    {
        printk(KERN_INFO "Failed to fetch path\n");
        mutex_unlock(&path_mutex);
        return 0;
    }
    pathname_len = strnlen(pathname, PATH_MAX);

    if (strncmp(pathname, target_path, target_path_len) == 0 && strstr(pathname, "//") == NULL && strstr(pathname, ".goutputstream-") == NULL && strstr(pathname, ".swp") == NULL && pathname[target_path_len] == '/' && strstr(pathname, ".swo") == NULL)
    {
        create_and_addnode(pathname,OP_WRITE,file->f_pos,regs->dx,data,current_uid().val,-1);
        printk(KERN_INFO "File %s is written", pathname);
    }
    mutex_unlock(&path_mutex);
    return 0;
}

int k_do_sys_open(struct kprobe *p, struct pt_regs *regs)
{
    int dfd = regs->di;
    const char __user *pathname_user = (const char __user *)regs->si;
    int flag = regs->dx;
    char *pathname;
    pid_t pid;
    umode_t mode = regs->r10;

    pid = task_pid_nr(current);
    pathname = get_absolute_path_from_dfd_pid(dfd, pid, pathname_user);
    if (pathname == NULL) {
        return 0;
    }
    if (strncmp(pathname, target_path, target_path_len) == 0 && strstr(pathname, "/4913") == NULL &&strstr(pathname, "~") == NULL && strstr(pathname, "//") == NULL && (pathname[target_path_len] == '\0' || pathname[target_path_len] == '/') && strstr(pathname, ".swp") == NULL && strstr(pathname, ".swx") == NULL)
    {   
        if (flag & O_CREAT)
        {  
            create_and_addnode(pathname,OP_CREATE,0,0,NULL,current_uid().val,mode);
            printk(KERN_INFO "File %s is created \n", pathname);
        }
    }

    return 0;
}

int k_vfs_unlink(struct kprobe *p, struct pt_regs *regs)
{
    struct dentry *dentry = (struct dentry *)regs->si;
    char *pathname;

    pathname = dentry_path_raw(dentry, path_buffer, PATH_MAX);

    if (IS_ERR(pathname))
    {
        printk(KERN_INFO "Failed to fetch path\\n");
        return 0;
    }

    if (strncmp(pathname, target_path, target_path_len) == 0 && strstr(pathname, "/4913") == NULL && strstr(pathname, "~") == NULL && strstr(pathname, "//") == NULL && (pathname[target_path_len] == '\0' || pathname[target_path_len] == '/')  && strstr(pathname, ".swp") == NULL && strstr(pathname, ".swx") == NULL && strstr(pathname, ":[") == NULL)
    {
        create_and_addnode(pathname,OP_DELETE,0,0,NULL,current_uid().val,-1);
        printk(KERN_INFO "File %s is delete \n", pathname);
    }

    return 0;
}

int k_do_mkdirat(struct kprobe *p, struct pt_regs *regs) {
    int dfd = regs->di;
    const char __user *pathname_user = (const char __user *)regs->si;
    char *pathname_kernel;
    umode_t mode = regs->dx;
    pid_t pid;

    pid = task_pid_nr(current);
    pathname_kernel = get_absolute_path_from_dfd_pid(dfd, pid, pathname_user);
    if (pathname_kernel == NULL) {
        return 0;
    }
    if (strncmp(pathname_kernel, target_path, strlen(target_path)) == 0 && pathname_kernel[target_path_len] == '/' && strstr(pathname_kernel, "//") == NULL) {
        create_and_addnode(pathname_kernel,OP_CREATEDIR,0,0,NULL,current_uid().val,mode);
        printk(KERN_INFO "Directory %s is created, mode: %ho\n ", pathname_kernel, mode);
    }

    return 0;
}

int k_rmdir(struct kprobe *p, struct pt_regs *regs) {
    int dfd = regs->di;
    const char __user *pathname_user = (const char __user *)regs->si;
    char *pathname_kernel;
    pid_t pid;

    pid = task_pid_nr(current);  // Get the current process ID

    pathname_kernel = get_absolute_path_from_dfd_pid(dfd, pid, pathname_user);
    if (strncmp(pathname_kernel, target_path, strlen(target_path)) == 0 && pathname_kernel[target_path_len] == '/' && strstr(pathname_kernel, "//") == NULL) {
        create_and_addnode(pathname_kernel,OP_DELETEDIR,0,0,NULL,current_uid().val,-1);
        printk(KERN_INFO "Directory %s is deleted", pathname_kernel);
    }

    return 0;
}

static struct kprobe kps[] = {
    {
        .symbol_name = "vfs_write",
        .pre_handler = k_vfs_write,
    },
    {
        .symbol_name = "do_sys_open",
        .pre_handler = k_do_sys_open,
    },
    {
        .symbol_name = "vfs_unlink",
        .pre_handler = k_vfs_unlink,
    },
    {
        .symbol_name = "do_mkdirat",
        .pre_handler = k_do_mkdirat,
    },
    {
        .symbol_name = "do_rmdir",
        .pre_handler = k_rmdir,
    },
};

static int __init our_init(void)
{
    int ret;
    size_t i;
    struct sockaddr_in addr;
    target_path_len = strlen(target_path);

    for (i = 0; i < sizeof(kps) / sizeof(kps[0]); ++i)
    {
        ret = register_kprobe(&kps[i]);
        if (ret < 0)
        {
            printk(KERN_INFO "register_kprobe failed for %s, returned %d\n", kps[i].symbol_name, ret);
            return ret;
        }
        printk(KERN_INFO "Planted kprobe at %s\n", kps[i].symbol_name);
    }
    // proc_create("iodata", 0, NULL, &proc_fops);

    // Create a socket
    ret = sock_create(AF_INET, SOCK_STREAM, 0, &sock);
    if (ret < 0) {
        printk(KERN_ERR "Failed to create socket, error %d\n", ret);
        return ret;
    }

    // Set up the address structure for the server
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8800);  // server port number
    if (in4_pton("172.18.44.10", -1, (u8 *)&addr.sin_addr.s_addr, -1, NULL) == 0) {
        printk(KERN_ERR "Failed to convert IP address\n");
        sock_release(sock);
        return -EINVAL;
    }

    // Connect the socket to the server
    ret = kernel_connect(sock, (struct sockaddr *)&addr, sizeof(addr), 0);
    if (ret < 0) {
        printk(KERN_ERR "Failed to connect to server, error %d\n", ret);
        sock_release(sock);
        return ret;
    }

    return 0;
}

static void __exit our_exit(void)
{
    size_t i;
    struct iodata_node *iter, *temp;
    for (i = 0; i < sizeof(kps) / sizeof(kps[0]); ++i)
    {
        unregister_kprobe(&kps[i]);
        printk(KERN_INFO "kprobe at %s unregistered\n", kps[i].symbol_name);
    }

    // remove_proc_entry("iodata", NULL);

    list_for_each_entry_safe(iter, temp, &iodata_list, list)
    {
        list_del(&iter->list);
        kfree(iter);
    }
    sock_release(sock);
}

module_init(our_init);
module_exit(our_exit);

MODULE_LICENSE("GPL");
