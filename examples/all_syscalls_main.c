/*
 * enable watching all system calls
 * For succinctness, only counts of events are shown periodically.
 */
#include <user_utils.h>

#include <libnitro.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <asm/unistd_64.h>

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
 * to listen to all system calls in the given virtual machine.
 * @param vm_pid	the PID of the process running the virtual machine
 * @return		0 iff successful
 */
static int setup(pid_t vm_pid)
{
	int n_vcpus;
	int vmfd;
	int err;

	if ((err = init_kvm())) {
		fprintf(stderr, "Unable to initialize KVM\n");
		goto INIT_FAIL;
	}

	vmfd = attach_vm(vm_pid);
	if (vmfd < 0) {
		err = -1;
		fprintf(stderr, "Unable to attach to VM");
		goto ATTACH_VM_FAIL;
	}

	n_vcpus = attach_vcpus();
	if (n_vcpus <= 0) {
		err = -1;
		fprintf(stderr, "Unable to attach to VCPUs");
		goto ATTACH_VCPUS_FAIL;
	}

	/** Start listening for all system calls. */
	if ((err = set_all_syscall_trap())) {
		fprintf(stderr, "Unable to listen for all system calls");
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

/* the number of syscall or sysret events before displaying information */
#define EVENT_THROTTLE	100
/* the largest known system call to count individually */
#define MAX_SYSCALL	__NR_finit_module

/* the table of counts for known system calls */
static unsigned long known_syscall_count[MAX_SYSCALL + 1] = {0};
/* the count of unknown system calls */
static unsigned long unknown_syscall_count = 0;
/* the total number of system calls */
static unsigned long total_syscall_count = 0;
/* the total number of system call returns */
static unsigned long total_sysret_count = 0;

/*
 * Keep count of system calls, and report unknown system call number.
 * @param syscall_cmd	the system call number
 * @param cr3		process identifier, for displaying message
 *			about unknown system call number.
 */
static void record_syscall(__u64 syscall_cmd, addr_t cr3)
{
	total_syscall_count++;

	if (syscall_cmd > __NR_finit_module) {
		printf("Unknown system call number, %llu.\n", syscall_cmd);
		unknown_syscall_count++;
	} else {
		known_syscall_count[syscall_cmd]++;
	}

}

/*
 * Report system calls by type and total.
 */
static void report_syscalls()
{
	int syscall_i;

	printf("System calls:\n");
	for (syscall_i = 0; syscall_i <= MAX_SYSCALL; syscall_i++) {
		printf("%d:\t\t%lu\n", syscall_i,
		       known_syscall_count[syscall_i]);
	}
	printf("unknown:\t%lu\n", unknown_syscall_count);
	printf("________________\n");
	printf("total:\t\t%lu\n", total_syscall_count);
}

/*
 * Report sysret count.
 */
static void report_sysrets()
{
	printf("Exited %lu times from syscall.\n", total_sysret_count);
}

/*
 * Count events, and report if threshold has been met.
 * @return	0 iff successful
 */
static int check_loop_event()
{
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	union event_data event_data;
	int event;

	event = get_event(0, &event_data);

	if (event < 0) {
		perror("Failed to fetch event");
		return -1;
	}

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
		record_syscall(regs.rax, sregs.cr3);
		if (total_syscall_count % EVENT_THROTTLE == 0) {
			report_syscalls();
		}
		break;
	case KVM_NITRO_EVENT_SYSRET:
		total_sysret_count++;
		if (total_sysret_count % EVENT_THROTTLE == 0) {
			report_sysrets();
		}
		break;
	case KVM_NITRO_EVENT_ERROR:
		fprintf(stderr, "Error event. Exiting.\n");
		return -1;
	default:
		fprintf(stderr, "Unknown event, %d. Exiting.\n", event);
		return -1;
	}

	return 0;
}

/*
 * Cleanup procedure to stop listening to system calls,
 * close the KVM file descriptor, and show a final report.
 */
static void cleanup()
{
	unset_syscall_trap();
	close_kvm();

	printf("Final Report:\n");
	report_syscalls();
	report_sysrets();
}

/*
 * Perform all the steps,
 * now that the parameters have been read from the command line.
 * @param vm_pid	the PID of the process running the virtual machine
 * @return		0 iff successful
 */
static int track(pid_t vm_pid)
{
	int err;

	if (setup(vm_pid)) {
		return -1;
	}

	running = 1;
	signal(SIGINT, handle_stop);
	while (running) {
		int cont_err;
		err = check_loop_event();

		cont_err = continue_vm(0);
		if (err) {
			break;
		}
		if (cont_err) {
			fprintf(stderr,
				"Something went wrong when continuing.\n");
			err = cont_err;
			break;
		}
	}

	cleanup();

	return err;
}

/*
 * The first argument after the program name
 * is the PID of the virtual machine process.
 */
#define QEMU_PID_ARG		1

int main(int argc, char *argv[])
{
	const char *vm_pid_str;
	pid_t vm_pid;

	if (argc <= QEMU_PID_ARG) {
		fprintf(stderr, "Usage: [qemu pid]\n");
		return -1;
	}

	vm_pid_str = argv[QEMU_PID_ARG];
	if (safe_atoi(&vm_pid, vm_pid_str)) {
		fprintf(stderr, "Invalid format for PID: \"%s\".\n",
			vm_pid_str);
	}

	return track(vm_pid);
}
