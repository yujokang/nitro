#include <libnitro.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

static int running;

static void handle_stop(int signum)
{
	running = 0;
}

static int setup(pid_t vm_pid, int *syscalls, unsigned n_syscalls)
{
	int n_vcpus;
	int vmfd;
	int err;

	if ((err = init_kvm())) {
		fprintf(stderr, "Unable to initialize KVM\n");
		goto INIT_FAIL;
	}

	vmfd = attach_vm(vm_pid);
	printf("attach_vm returned %d.\n", vmfd);
	if (vmfd < 0) {
		err = -1;
		fprintf(stderr, "Unable to attach to VM");
		goto ATTACH_VM_FAIL;
	}

	n_vcpus = attach_vcpus();
	printf("attach_vcpus returned %d.\n", n_vcpus);
	if (n_vcpus <= 0) {
		err = -1;
		fprintf(stderr, "Unable to attach to VCPUs");
		goto ATTACH_VCPUS_FAIL;
	}

	if ((err = set_syscall_trap(syscalls, n_syscalls))) {
		fprintf(stderr, "Unable to listen for system calls");
		goto SET_SYSCALL_TRAP_FAIL;
	}

	return 0;
SET_SYSCALL_TRAP_FAIL:
ATTACH_VCPUS_FAIL:
ATTACH_VM_FAIL:
	close_kvm();
INIT_FAIL:
	printf(". Exiting.\n");
	return err;
}

static int check_loop_event()
{
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	union event_data event_data;
	int event;

	event = get_event(0, &event_data);

	if (get_regs(0, &regs)) {
		printf("Error getting general registers. Exiting.\n");
		return -1;
	}
	if (get_sregs(0, &sregs)) {
		printf("Error getting system registers. Exiting.\n");
		return -1;
	}
	switch (event) {
	case KVM_NITRO_EVENT_SYSCALL:
		printf("Syscall entry by cr3 =\t0x%llx, id = %lx:\n",
		       sregs.cr3, event_data.syscall);
		printf("\tSyscall command = %llu\n", regs.rax);
		break;
	case KVM_NITRO_EVENT_SYSRET:
		printf("Syscall exit by cr3 =\t0x%llx, id = %lx:\n",
		       sregs.cr3, event_data.syscall);
		printf("\tReturn value= %llu\n", regs.rax);
		break;
	case KVM_NITRO_EVENT_ERROR:
		fprintf(stderr, "Error event. Exiting.\n");
		return -1;
	}

	return 0;
}

static void cleanup()
{
	int ret;

	ret = unset_syscall_trap();
	printf("unset_syscall_trap returned %d.\n", ret);

	ret = close_kvm();
	printf("close_kvm returned %d.\n", ret);
}

static int track(pid_t vm_pid, int *syscalls, unsigned n_syscalls)
{
	int err;

	if (setup(vm_pid, syscalls, n_syscalls)) {
		return -1;
	}

	running = 1;
	signal(SIGINT, handle_stop);
	while (running) {
		int cont_err;
		err = check_loop_event();

		cont_err = continue_vm(0);
		printf("continue_vm returned %d.\n", cont_err);
		if (err) {
			return err;
		}
		if (cont_err) {
			return cont_err;
		}
	}

	cleanup();

	return err;
}

#define MAX_DIGITS	10
#define BASE		10
#define LEAST_DIGIT	'0'

int safe_atoi(int *out, const char *src)
{
	int total = 0;
	unsigned char_i;

	for (char_i = 0; (char_i < MAX_DIGITS); char_i++) {
		char current_char = src[char_i];
		int current_value;

		if (LEAST_DIGIT <= current_char &&
		    (current_value = (current_char - LEAST_DIGIT)) < BASE) {
			total = BASE * total + current_value;
		} else if (current_char == '\0') {
			*out = total;

			return 0;
		} else {
			return -1;
		}
	}

	return -1;
}

#define N_DEFAULT_SYSCALLS	3
static int default_syscalls[N_DEFAULT_SYSCALLS] = {
	159, /* adjtimex */
	74, /* fsync */
	170, /* sethostname */
};

#define QEMU_PID_ARG		1
#define SYSCALL_ARGS_START	(QEMU_PID_ARG + 1)

int main(int argc, char *argv[])
{
	const char *vm_pid_str;
	pid_t vm_pid;
	unsigned n_syscalls;
	int *syscalls;
	unsigned syscall_i;

	if (argc <= QEMU_PID_ARG) {
		fprintf(stderr, "Usage: [qemu pid] [system call numbers...]\n");
		return -1;
	}

	vm_pid_str = argv[QEMU_PID_ARG];
	if (safe_atoi(&vm_pid, vm_pid_str)) {
		fprintf(stderr, "Invalid format for PID: \"%s\".\n",
			vm_pid_str);
	}
	n_syscalls = (unsigned) argc - SYSCALL_ARGS_START;

	if (n_syscalls > 0) {
		syscalls = alloca(sizeof(int) * n_syscalls);

		for (syscall_i = 0; syscall_i < n_syscalls; syscall_i++) {
			const char *syscall_str = argv[syscall_i +
						       SYSCALL_ARGS_START];
			int err = safe_atoi(&syscalls[syscall_i], syscall_str);

			if (err < 0) {
				fprintf(stderr, "Unable to parse system call "
					"%u: \"%s\"", syscall_i, syscall_str);
				return -1;
			}
		}
	} else {
		n_syscalls = N_DEFAULT_SYSCALLS;
		syscalls = default_syscalls;
	}

	return track(vm_pid, syscalls, n_syscalls);
}
