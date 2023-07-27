#include "pro_stopio.h"
// #include "proc_entry.h"

static struct mutex path_mutex;
static char *target_path = "/home/ildnyy/test";

static LIST_HEAD(iodata_list);
static DEFINE_MUTEX(list_mutex); // 用于链表访问的互斥锁

static const struct file_operations proc_fops = {
    .read = iodata_read,
};

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

int k_vfs_write(struct kprobe *p, struct pt_regs *regs)
{
    struct file *file = (struct file *)regs->di; /*regs为传入的寄存器结构体指针*/
    struct dentry *dentry = file->f_path.dentry;
    char *data = (char *)regs->si;
    char *pathname;
    int pathname_len;
    struct iodata io_data = {
        .op_type = OP_WRITE,
        .offset = regs->si,
        .length = regs->dx,
        .user_id = current_uid().val};

    mutex_lock(&path_mutex);

    pathname = d_path(&file->f_path, path_buffer, PATH_MAX);

    if (IS_ERR(pathname))
    {
        printk(KERN_INFO "Failed to fetch path\n");
        mutex_unlock(&path_mutex);
        return 0;
    }
    pathname_len = strnlen(pathname, PATH_MAX);
    /* Check if the path starts with the target path */
    if (strncmp(pathname, target_path, min(pathname_len, strlen(target_path))) == 0 && strstr(pathname, ".goutputstream-") == NULL && strstr(pathname, ".swp") == NULL && pathname[pathname_len - 1] != '~' && strstr(pathname, ".swo") == NULL)
    {
        struct iodata_node *new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
        if (!new_node)
        {
            printk(KERN_ERR "Failed to allocate memory for new iodata node.\n");
            return -ENOMEM;
        }
        new_node->data = io_data;
        strncpy(new_node->data.path, pathname, PATH_MAX);
        strncpy(new_node->data.data, data, min(regs->dx, MAX_IO_SIZE));
        ktime_get_ts(&new_node->data.timestamp);

        list_add_tail(&new_node->list, &iodata_list);
    }
    mutex_unlock(&path_mutex);
    return 0;
}

int k_do_sys_open(struct kprobe *p, struct pt_regs *regs)
{
    int dfd = (int)regs->di;
    const char __user *pathname_user = (const char __user *)regs->si;
    int flags = (int)regs->dx;
    char *pathname;
    struct kstat stat;
    struct path path;
    int exists;
    int pathname_len; 
    size_t target_path_len = strlen(target_path);
    
    if (user_path_at(AT_FDCWD, pathname_user, LOOKUP_FOLLOW, &path) == 0){
        pathname = dentry_path_raw(path.dentry, path_buffer, PATH_MAX);
        path_put(&path);
        pathname_len = strnlen(pathname, PATH_MAX);
        if (strncmp(pathname, target_path, target_path_len) == 0 && (pathname[target_path_len] == '\0' || pathname[target_path_len] == '/') && strstr(pathname, ".goutputstream-") == NULL && strstr(pathname, ".swp") == NULL && strstr(pathname, ".swo") == NULL && pathname[pathname_len - 1] != '~')
        {
            exists = vfs_stat(pathname, &stat);
            if (flags & O_CREAT && exists != 0)
            {
                printk(KERN_INFO "File %s is created, flags=%d\\n", pathname, flags);
            }
        }
    }
    
    return 0;
}

int k_vfs_create(struct kprobe *p, struct pt_regs *regs)
{
    const char __user *pathname_user = (const char __user *)regs->si;
    char *pathname;
    struct path path;
    int pathname_len;

    if (user_path_at(AT_FDCWD, pathname_user, LOOKUP_FOLLOW, &path) == 0){
        pathname = dentry_path_raw(path.dentry, path_buffer, PATH_MAX);
        path_put(&path);
        int pathname_len = strnlen(pathname, PATH_MAX);
        if (strncmp(pathname, target_path, min(pathname_len, strlen(target_path))) == 0 && strstr(pathname, ".goutputstream-") == NULL && strstr(pathname, ".swp") == NULL && strstr(pathname, ".swo") == NULL && pathname[pathname_len - 1] != '~')
        {
            printk(KERN_INFO "File %s is created\n", pathname);
        }
    }

    return 0;
}

int k_do_mkdirat(struct kprobe *p, struct pt_regs *regs) {
    int dfd = regs->di;
    const char __user *pathname_user = (const char __user *)regs->si;
    umode_t mode = regs->dx;
    char pathname[PATH_MAX];
    char *pathname_kernel;
    struct path path;

    // Copy the pathname from user space to kernel space
    if (copy_from_user(pathname, pathname_user, PATH_MAX) != 0) {
        return 0;  // Return if the copy failed
    }

    // Convert the pathname to a kernel space pathname
    pathname_kernel = get_absolute_path_from_user(pathname);
    if (pathname_kernel == NULL) {
        return 0;  // Return if the conversion failed
    }

    // Check if the pathname starts with the target path
    if (strncmp(pathname_kernel, target_path, strlen(target_path)) == 0) {
        printk(KERN_INFO "Directory %s is created with mode %o\n", pathname_kernel, mode);
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
    int pathname_len = strnlen(pathname, PATH_MAX);

    if (strncmp(pathname, target_path, strlen(target_path)) == 0 && strstr(pathname, ".goutputstream-") == NULL && strstr(pathname, ".swp") == NULL && pathname[pathname_len - 1] != '~' && strstr(pathname, ".swx") == NULL && strstr(pathname, ".swo") == NULL)
    {
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
};

static int __init our_init(void)
{
    int ret;
    size_t i;

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

char *get_absolute_path_from_user(const char __user *pathname_user)
{
    char *pathname_kernel;
    char *abs_path;
    struct path path;

    // Copy path from user space to kernel space
    if (copy_from_user(path_buffer1, pathname_user, PATH_MAX) != 0)
    {
        return NULL;
    }
    mutex_lock(&path_mutex);
    // Construct path struct
    if (kern_path(path_buffer1, LOOKUP_FOLLOW, &path) == 0)
    {
        abs_path = d_path(&path, path_buffer, PATH_MAX);
        path_put(&path);
    }
    mutex_unlock(&path_mutex);
    return abs_path;
}

module_init(our_init);
module_exit(our_exit);

MODULE_LICENSE("GPL");
