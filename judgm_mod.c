#include<linux/module.h>
#include<linux/kernel.h>
#include<linux/kdev_t.h>
#include<linux/device.h>
#include<linux/cdev.h>
#include<linux/fs.h>

#include"judgm_mod.h"
#include"judgm.h"
#include"judge_com.h"

static int __init mod_init(){
    alloc_chrdev_region(&mod_dev,0,1,"judgm");
    mod_class = class_create(THIS_MODULE,"chardev");
    device_create(mod_class,NULL,mod_dev,NULL,"judgm");
    cdev_init(&mod_cdev,&mod_fops);
    cdev_add(&mod_cdev,mod_dev,1);

    judgm_proc_init();
    judgm_security_hook();
    judgm_syscall_hook();

    pr_alert("judgm:Init\n");
    return 0;
}
static void __exit mod_exit(){
    cdev_del(&mod_cdev);
    device_destroy(mod_class,mod_dev);
    class_destroy(mod_class);
    unregister_chrdev_region(mod_dev,1);

    judgm_syscall_unhook();
    judgm_security_unhook();

    pr_alert("judgm:Exit\n");
}
module_init(mod_init);
module_exit(mod_exit);
MODULE_LICENSE("GPL");

static long mod_ioctl(struct file *file,unsigned int cmd,unsigned long arg){
    int ret;

    ret = -1;
    switch(cmd){
	case IOCTL_PROC_ADD:
	    ret = judgm_proc_add(arg);
	    break;
	case IOCTL_PROC_GET:
	    ret = judgm_proc_get(arg); 
	    break;
	case IOCTL_PROC_DEL:
	    ret = judgm_proc_del(arg);
	    break;
    }

    return ret;
}
