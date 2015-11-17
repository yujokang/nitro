/*
 * a bare-minimum example, that simply listens for chosen system calls,
 * and displays general information about them.
 * Note that we assume only one VCPU,
 * so the VCPU parameters in get_event, get_regs, get_sregs and continue_vm
 * are 0.
 */
#include <user_utils.h>

#include <libnitro.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * the flag indicating that this program should keep listening
 * for system calls.
 */
static int running;

/*
 * When receiving a chosen signal (eg. SIGINT),
 * clear "running" to initiate cleanup.
 * @param signum	the received signal
 */
static void handle_stop(int signum)
{
	running = 0;
}

/*
 * Perform one-time setup
 * to listen to system calls in the given virtual machine.
 * @param vm_pid	the PID of the process running the virtual machine
 * @param syscalls	the array of system calls
 * @param n_syscalls	the length of syscalls
 * @return		0 iff successful
 */
static int setup(pid_t vm_pid, int *syscalls, unsigned n_syscalls)
{
	int n_vcpus;
	int vmfd;
	int err;

	/* setup 1: Open the KVM module, ie. open the device file. */
	if ((err = init_kvm())) {
		fprintf(stderr, "Unable to initialize KVM\n");
		goto INIT_FAIL;
	}

	/*
	 * setup 2: Attach to the virtual machine running under the given PID.
	 */
	vmfd = attach_vm(vm_pid);
	printf("attach_vm returned %d.\n", vmfd);
	if (vmfd < 0) {
		err = -1;
		fprintf(stderr, "Unable to attach to VM");
		goto ATTACH_VM_FAIL;
	}

	/* setup 3: Attach to the VCPUS of the virtual machine. */
	n_vcpus = attach_vcpus();
	printf("attach_vcpus returned %d.\n", n_vcpus);
	if (n_vcpus <= 0) {
		err = -1;
		fprintf(stderr, "Unable to attach to VCPUs");
		goto ATTACH_VCPUS_FAIL;
	}

	/** setup 4: Start listening for the given system calls. */
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

/*
 * Report on a single event during the loop.
 * @return		0 iff successful
 */
static int check_loop_event()
{
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	union event_data event_data;
	int event;

	event = get_event(0, &event_data);

	/*
	 * check_loop_event 1:
	 * Fetch the directly-accessible integer registers.
	 */
	if (get_regs(0, &regs)) {
		printf("Error getting general registers. Exiting.\n");
		return -1;
	}
	/*
	 * check_loop_event 2:
	 * Fetch the segment and memory management registers.
	 */
	if (get_sregs(0, &sregs)) {
		printf("Error getting system registers. Exiting.\n");
		return -1;
	}
	switch (event) {
	/*
	 * check_loop_event 3 a:
	 * syscall has been called, indicating a system call from user space,
	 * so that the information includes the system call parameters.
	 */
	case KVM_NITRO_EVENT_SYSCALL:
		printf("Syscall entry by cr3 =\t0x%llx, id = %lx:\n",
		       sregs.cr3, event_data.syscall);
		printf("\tSyscall command = %llu\n", regs.rax);
		/*
		 * the current instruction pointer,
		 * which should be the entry point to the system call handler
		 * in kernel space
		 */
		printf("\tInstruction pointer =\t0x%llx\n", regs.rip);
		/*
		 * the return pointer, which should be right after
		 * the user space address that made the system call
		 */
		printf("\tReturn pointer =\t0x%llx\n", regs.rcx);
		break;
	/*
	 * check_loop_event 3 b:
	 * sysret has been called, indicating a return from kernel space,
	 * so that the information includes the return value of the system call.
	 */
	case KVM_NITRO_EVENT_SYSRET:
		printf("Syscall exit by cr3 =\t0x%llx, id = %lx:\n",
		       sregs.cr3, event_data.syscall);
		printf("\tReturn value = %llu\n", regs.rax);
		/*
		 * the current instruction pointer, which should be
		 * the return pointer from the corresponding syscall event
		 */
		printf("\tInstruction pointer =\t0x%llx\n", regs.rip);
		break;
	/* check_loop_event 3 c: An unexpected error event has occured. */
	case KVM_NITRO_EVENT_ERROR:
		fprintf(stderr, "Error event. Exiting.\n");
		return -1;
	}

	return 0;
}

/*
 * Cleanup procedure to stop listening to system calls,
 * and close the KVM file descriptor.
 */
static void cleanup()
{
	int ret;

	/* cleanup 1: Stop listening to system calls. */
	ret = unset_syscall_trap();
	printf("unset_syscall_trap returned %d.\n", ret);

	/* cleanup 2: Close the KVM module, ie. close the device file. */
	ret = close_kvm();
	printf("close_kvm returned %d.\n", ret);
}

/*
 * Perform all the steps,
 * now that the parameters have been read from the command line.
 * @param vm_pid	the PID of the process running the virtual machine
 * @param syscalls	the array of system calls
 * @param n_syscalls	the length of syscalls
 * @return		0 iff successful
 */
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
			break;
		}
		if (cont_err) {
			err = cont_err;
			break;
		}
	}

	cleanup();

	return err;
}

/*
 * default system call numbers for 64-bit Linux only
 * Note that interrupt-based system calls
 * still use the 32-bit system call numbers.
 */
#define N_DEFAULT_SYSCALLS	3
static int default_syscalls[N_DEFAULT_SYSCALLS] = {
	159, /* adjtimex */
	74, /* fsync */
	170, /* sethostname */
};

/*
 * The first argument after the program name
 * is the PID of the virtual machine process.
 */
#define QEMU_PID_ARG		1
/* Optionally, the user can append system call numbers. */
#define SYSCALL_ARGS_START	(QEMU_PID_ARG + 1)

int main(int argc, char *argv[])
{
	const char *vm_pid_str;
	pid_t vm_pid;
	unsigned n_syscalls;
	int *syscalls;
	unsigned syscall_i;

	/* Convert command line arguments. */
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
					"%u, \"%s\". "
					"It must be an integer.\n",
					syscall_i, syscall_str);
				return -1;
			}
		}
	} else {
		n_syscalls = N_DEFAULT_SYSCALLS;
		syscalls = default_syscalls;
	}

	/* Start using the nitro library. */
	return track(vm_pid, syscalls, n_syscalls);
}
