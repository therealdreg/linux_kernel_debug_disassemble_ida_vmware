/*
 * lkmsym 0.1b
 * GPL <2020>
 * -
 * WARNING!!: This is a mod based in prsyms2 for printing all kernel symbols by Sam Protsenko:
 * https://stackoverflow.com/questions/37978245/how-to-dump-list-all-kernel-symbols-with-addresses-from-linux-kernel-module
 * -
 * mod by David Reguera Garcia aka Dreg
 * https://github.com/therealdreg/linux_kernel_debug_disassemble_ida_vmware
 * Dreg@fr33project.org - http://www.fr33project.org/ - https://github.com/therealdreg
 * twitter: @therealdreg
*/

#include <linux/device.h>
#include <linux/fs.h>
#include <linux/kallsyms.h>
#include <linux/module.h>
#include <linux/miscdevice.h>
#include <linux/sizes.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#define DEVICE_NAME         "lkmsym"
#define SYMBOLS_BUF_SIZE    SZ_512M

struct symbols {
    char *buf;
    size_t pos;
};

static struct symbols symbols;

static ssize_t lkmsym_read(struct file *file, char __user *buf, size_t count,
                            loff_t *pos)
{
    return simple_read_from_buffer(buf, count, pos, symbols.buf,
                                   symbols.pos);
}

static const struct file_operations lkmsym_fops = {
    .owner  = THIS_MODULE,
    .read   = lkmsym_read,
};

static struct miscdevice lkmsym_misc = {
    .minor  = MISC_DYNAMIC_MINOR,
    .name   = DEVICE_NAME,
    .fops   = &lkmsym_fops,
};

static int lkmsym_store_symbol(void *data, const char *namebuf, struct module *module, unsigned long address)
{
    struct symbols *s = data;
    int count;

    /* Append address of current symbol */
#ifdef __x86_64
	#define hexfmt "%016lX U "
#else
	#define hexfmt "%08lX U "
#endif
    count = sprintf(s->buf + s->pos, hexfmt, address);
    s->pos += count;

    /* Append name, offset, size and module name of current symbol */
    count = sprint_symbol(s->buf + s->pos, address);
    s->pos += count;
    s->buf[s->pos++] = '\n';

    if (s->pos >= SYMBOLS_BUF_SIZE)
        return -ENOMEM;

    return 0;
}

static int __init lkmsym_init(void)
{
    int ret;

    ret = misc_register(&lkmsym_misc);
    if (ret)
        return ret;

    symbols.pos = 0;
    symbols.buf = vmalloc(SYMBOLS_BUF_SIZE);
    if (symbols.buf == NULL) {
        ret = -ENOMEM;
        goto err1;
    }

    dev_info(lkmsym_misc.this_device, "Populating symbols buffer...\n");
    ret = kallsyms_on_each_symbol(lkmsym_store_symbol, &symbols);
    if (ret != 0) {
        ret = -EINVAL;
        goto err2;
    }
    symbols.buf[symbols.pos] = '\0';
    dev_info(lkmsym_misc.this_device, "Symbols buffer is ready!\n");

    return 0;

err2:
    vfree(symbols.buf);
err1:
    misc_deregister(&lkmsym_misc);
    return ret;
}

static void __exit lkmsym_exit(void)
{
    vfree(symbols.buf);
    misc_deregister(&lkmsym_misc);
}

module_init(lkmsym_init);
module_exit(lkmsym_exit);

MODULE_AUTHOR("Dreg mod based in prsyms2 by Sam Protsenko");
MODULE_DESCRIPTION("Module for printing all kernel symbols");
MODULE_LICENSE("GPL");
