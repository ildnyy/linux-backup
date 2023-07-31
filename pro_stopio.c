#include "pro_stopio.h"
static struct mutex path_mutex;
static DEFINE_MUTEX(list_mutex);
static LIST_HEAD(iodata_list);

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

int k_vfs_write(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file = (struct file *)regs->di; 
    struct dentry *dentry = file->f_path.dentry;
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

    if (strncmp(pathname, target_path, min(pathname_len, strlen(target_path))) == 0 && strstr(pathname, ".goutputstream-") == NULL && strstr(pathname, ".swp") == NULL && pathname[pathname_len - 1] != '~' && strstr(pathname, ".swo") == NULL)
    {
        create_and_addnode(pathname,OP_WRITE,regs->si,regs->dx,data,current_uid().val,-1);
        // struct iodata_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        // if (!new_node)
        // {
        //     printk(KERN_ERR "Failed to allocate memory for new iodata node.\n");
        //     return -ENOMEM;
        // }

        // new_node->data = io_data;
        // strncpy(new_node->data.path, pathname, PATH_MAX);
        // strncpy(new_node->data.data, data, min(regs->dx, MAX_IO_SIZE));
        // ktime_get_ts(&new_node->data.timestamp);

        // list_add_tail(&new_node->list, &iodata_list);
    }
    mutex_unlock(&path_mutex);
    return 0;
}

int k_do_sys_open(struct kprobe *p, struct pt_regs *regs)
{
    int dfd = (int)regs->di;
    int flags = (int)regs->dx;
    int exists;
    int pathname_len; 
    char *pathname;
    const char __user *pathname_user = (const char __user *)regs->si;
    struct kstat stat;
    struct path path;
    
    if (user_path_at(AT_FDCWD, pathname_user, LOOKUP_FOLLOW, &path) == 0){
        pathname = dentry_path_raw(path.dentry, path_buffer, PATH_MAX);
        path_put(&path);
        pathname_len = strnlen(pathname, PATH_MAX);
        if (strncmp(pathname, target_path, target_path_len) == 0 && (pathname[target_path_len] == '\0' || pathname[target_path_len] == '/') && strstr(pathname, ".goutputstream-") == NULL && strstr(pathname, ".swp") == NULL && strstr(pathname, ".swo") == NULL && strstr(pathname, ".swx") && pathname[pathname_len - 1] != '~')
        {   
            printk(KERN_INFO "file %s is open\n",pathname);
            exists = vfs_stat(pathname, &stat);
            if (flags & O_CREAT && exists != 0)
            {
                printk(KERN_INFO "File %s is created, flags=%d\\n", pathname, flags);
            }
        }
    }
    
    return 0;
}

struct iodata_node *create_and_addnode(const char *pathname, enum operation_type op_type, loff_t offset, size_t length, const unsigned char *data, uid_t user_id, umode_t mode) 
{
    struct iodata_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node) {
        printk(KERN_ERR "Failed to allocate memory for new iodata node.\n");
        return NULL;
    }

    new_node->data.op_type = op_type;
    strncpy(new_node->data.path, pathname, PATH_MAX);
    new_node->data.offset = offset;
    new_node->data.length = length;
    if (data != NULL) {
        memcpy(new_node->data.data, data, min(length, (size_t)MAX_IO_SIZE));
    } else {
        memset(new_node->data.data, 0, MAX_IO_SIZE);
    }
    ktime_get_ts(&new_node->data.timestamp);
    new_node->data.user_id = user_id;
    new_node->data.mode = mode;
    list_add_tail(&new_node->list, &iodata_list);
    
    return new_node;
}

int k_do_mkdirat(struct kprobe *p, struct pt_regs *regs) {
    int dfd = regs->di;
    const char __user *pathname_user = (const char __user *)regs->si;
    char pathname[PATH_MAX];
    char *pathname_kernel;
    umode_t mode = regs->dx;
    struct path path;
    pid_t pid;

    pid = task_pid_nr(current);
    pathname_kernel = get_absolute_path_from_dfd_pid(dfd, pid, pathname_user);
    if (pathname_kernel == NULL) {
        return 0;
    }
    if (strncmp(pathname_kernel, target_path, strlen(target_path)) == 0) {
        create_and_addnode(pathname_kernel,OP_CREATEIDR,0,0,NULL,current_uid().val,mode);
        printk(KERN_INFO "Directory %s is created \n", pathname_kernel);
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
    if (strncmp(pathname_kernel, target_path, strlen(target_path)) == 0) {
        create_and_addnode(pathname_kernel,OP_DELETEDIR,0,0,NULL,current_uid().val,-1);
        printk(KERN_INFO "Directory %s is deleted with mode %o\n", pathname_kernel);
    }

    return 0;
}

int k_vfs_unlink(struct kprobe *p, struct pt_regs *regs)
{
    struct dentry *dentry = (struct dentry *)regs->si;
    char *pathname;
    struct iodata io_data = {
        .op_type = OP_DELETE,
        .user_id = current_uid().val
    };

    pathname = dentry_path_raw(dentry, path_buffer, PATH_MAX);

    if (IS_ERR(pathname))
    {
        printk(KERN_INFO "Failed to fetch path\\n");
        return 0;
    }
    int pathname_len = strnlen(pathname, PATH_MAX);

    if (strncmp(pathname, target_path, strlen(target_path)) == 0 && (pathname[target_path_len] == '\0' || pathname[target_path_len] == '/') && strstr(pathname, ".goutputstream-") == NULL && strstr(pathname, ".swp") == NULL && pathname[pathname_len - 1] != '~' && strstr(pathname, ".swx") == NULL && strstr(pathname, ".swo") == NULL)
    {
        struct iodata_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        if (!new_node)
        {
            printk(KERN_ERR "Failed to allocate memory for new iodata node.\n");
            return -ENOMEM;
        }
        new_node->data = io_data;
        strncpy(new_node->data.path, pathname, PATH_MAX);
        ktime_get_ts(&new_node->data.timestamp);
        list_add_tail(&new_node->list, &iodata_list);
        printk(KERN_INFO "File %s is deleted\n", pathname);
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
    proc_create("iodata", 0, NULL, &proc_fops);
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

    remove_proc_entry("iodata", NULL);

    list_for_each_entry_safe(iter, temp, &iodata_list, list)
    {
        list_del(&iter->list);
        kfree(iter);
    }
}

module_init(our_init);
module_exit(our_exit);

MODULE_LICENSE("GPL");
