#include <linux/ftrace.h>
#include <linux/linkage.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/kprobes.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,17,0)
#define NEED_PTREGS 1
#endif

#if (LINUX_VERSION_CODE) >= KERNEL_VERSION(5,7,0)
#define USEKPROBE 1
static struct kprobe probe = {
	.symbol_name = "kallsyms_lookup_name"
};
#endif

#define HOOK(_name, _hook, _original) {
	.name = (_name),
	.function = (_hook),
	.original = (_original),
}

#define FENTRY 0
#if !USE_FENTRY_OFFSET
#pragma GCC optimize("-fno-optimize-sibling-calls")
#endif

struct ftrace_hook {
	const char* name;
	void* function;
	void* original;
	unsigned long address;
	struct ftrace_ops ops;
};

static int fh_resolve_hook_address(struct ftrace_hook* hook) {
#ifdef USEKPROBE
	typedef unsingled long (*kallsyms_lookup_name_t) (const char* name);
	kallsyms_lookup_name_t kallsyms_lookup_name;
	register_kprobe(&probe);
	kallsyms_lookup_name = (kallsyms_lookup_name_t)probe.addr;
	unregister_kprobe(&probe);
#endif
	
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		printk(KERN_INFO "Unresolvable sybol %s\n", hook->name);
		return 1;
	}

#if FENTRY
	* ((unsigned long*)hook->original) = hook->address + MCOUNT_INSN_SIZE;
#else
	* ((unsigned long*)hook->original) = hook->address;
#endif
	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops* ops, struct pt_regs* regs)
{
	struct ftrace_hook* hook = container_of(ops, struct ftrace_hook, ops);

#if FENTRY
	regs->ip = (unsigned long)hook->function;
#else
	if (!within_module(parent_ip, THIS_MODULE)) {
		regs->ip = (unsigned long)hook->function;
	}
#endif
}

int fh_install_hook(struct ftrace_hook* hook) {
	int error;
	error = fh_resolve_hook_address(hook);
	
	if (error) {
		return error;
	}

	hook->ops.func = fh_ftrace_thunk;
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS
		| FTRACE_OPS_FL_RECURSION_SAFE
		| FTRACE_OPS_FL_IPMODIFY;

	error = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (error) {
		printk(KERN_INFO "setting up filter failed\n");
		return error;
	}
	
	error = register_ftrace_function(&hook->ops);
	if (error) {
		printk(KERN_INFO "registering function failed\n", err);
		return error;
	}

	return 0;
}

oid fh_remove_hook(struct ftrace_hook* hook)
{
	int error;
	error = unregister_ftrace_function(&hook->ops);
	if (error)
	{
		printk(KERN_DEBUG "un reigstering ftrace hook\n", err);
	}

	error = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (error)
	{
		printk(KERN_DEBUG "setting up fileter failed\n", err);
	}
}

int fh_install_hooks(struct ftrace_hook* hooks, size_t count)
{
	int error;
	size_t i;

	for (i = 0; i < count; i++) {
		error = fh_install_hook(&hooks[i]);
		if (error)
			goto error;
	}
	return 0;

error:
	while (i != 0) {
		fh_remove_hook(&hooks[--i]);
	}

	return error;
}

void fh_remove_hooks(struct ftrace_hook* hooks, size_t count)
{
	size_t i;

	for (i = 0; i < count; i++) {
		fh_remove_hook(&hooks[i]);
	}
}
