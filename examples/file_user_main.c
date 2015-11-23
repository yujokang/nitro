/*
 * an example of tracking a specific process.
 * Repeatedly looks for a process that opens a specified file,
 * and tracks it until it exits,
 * after which this program looks for another process that opens the same file.
 * Read string_params_main.c for requirements for reading the file name
 * in the open() system call.
 */
#include <user_utils.h>

#include <libnitro.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

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

static int open_syscall[1] = {2};

static int setup_search()
{
	printf("Starting search for process opening given file.\n");
	if (set_syscall_trap(open_syscall, 1)) {
		perror("Unable to listen for open");
		return -1;
	}

	return 0;
}

/*
 * Set up the connection to KVM, and open and map the RAM file.
 * @param vm_pid	the PID of the virtual machine process
 * @param file_path	the path to the RAM file
 * @param ram		the state of the RAM file,
 *			used throughout the execution of this program
 * @return		0 iff successful
 */
static int setup(pid_t vm_pid, const char *file_path, struct ram_file *ram)
{
	int n_vcpus;
	int vmfd;
	int err;

	if ((err = init_ram_file(ram, file_path))) {
		fprintf(stderr, "Unable to initialize RAM with file \"%s\".\n",
			file_path);
		perror("");
		err = -1;
		goto MEM_FAIL;
	}

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

	/* Setup searching for process that opens the specified file. */
	if ((err = setup_search())) {
		fprintf(stderr, "Unable to setup process search");
		goto SETUP_SEARCH_FAIL;
	}

	return 0;
SETUP_SEARCH_FAIL:
ATTACH_VCPUS_FAIL:
ATTACH_VM_FAIL:
	close_kvm();
INIT_FAIL:
	destroy_ram_file(ram);
MEM_FAIL:
	printf(". Exiting.\n");
	return err;
}

/*
 * After the desired process has been found,
 * start watching all of its system calls.
 * @param process_cr3	the process to watch
 * @return		0 iff successful
 */
static int setup_watch(ulong process_cr3)
{
	int err = add_process_trap(process_cr3);

	if (err) {
		return err;
	}

	if ((err = set_all_syscall_trap())) {
		remove_process_trap(process_cr3);
	}

	return err;
}

/*
 * Check the event for if it is a system call that opens
 * the specified file, and if so, watch the process.
 * @param ram		the ram file for accessing the file name parameter
 * @param regs		the user-accessible registers
 *			containing the system call arguments
 * @param sregs		the system registers containing the current cr3 value
 * @param event		the event type, indicating if it a system call
 * @param watched_file	the file whose opening indicates that
 *			the process should be tracked
 * @return		1 if the process opened the specified file,
 *				and could be watched,
 *			-1 if the process opened the specified file,
 *				and could not be watched,
 *			0 otherwise
 */
static int
check_search_loop(struct ram_file *ram, struct kvm_regs *regs,
		  struct kvm_sregs *sregs, int event, const char *watched_file)
{
	int ret = 0;

	if (event == KVM_NITRO_EVENT_SYSCALL) {
		char *watched_file_arg = copy_string(regs->rdi, ram);

		ret = 0;
		if (watched_file_arg == NULL) {
			fprintf(stderr,
				"Failed to translate file name at 0x%llx.\n",
				regs->rdi);
		} else {
			printf("Opened file \"%s\"\n", watched_file_arg);

			if (strcmp(watched_file_arg, watched_file) == 0) {
				printf("This is the process we want to watch, "
				       "and its cr3 value is 0x%llx.\n",
				       sregs->cr3);
				if (setup_watch(sregs->cr3)) {
					fprintf(stderr,
						"Failed to select process.\n");
					ret = -1;
				} else {
					ret = 1;
				}
			}

			free(watched_file_arg);
		}
	}

	return ret;
}

/* a one-thread exit system call */
#define EXIT_SYSCALL		60
/* a process-wide exit system call */
#define EXIT_GROUP_SYSCALL	231

/*
 * Watch all the system calls in a process,
 * reporting the same information as in the basic example,
 * but don't display cr3, which is implicit,
 * and stop watching, and start searching if the process exits.
 * @param regs		the user-accessible registers
 * @param sregs		the system registers containing the current cr3 value
 *			for when the process is to be removed
 * @param event		the event type to report
 * @param syscall	identifier for the system call
 * @return		1 if the tracked process has exited
 *				and this program will search for a new one,
 *			-1 if the tracked process has exited,
 *				but this program is unable to search
 *				for a new one,
 *			0 otherwise
 */
static int check_watch_loop(struct kvm_regs *regs, struct kvm_sregs *sregs,
			    int event, ulong syscall)
{
	int ret = 0;

	switch (event) {
	case KVM_NITRO_EVENT_SYSCALL: {
		__u64 syscall_number = regs->rax;

		printf("Syscall entry id = %lx:\n", syscall);
		printf("\tSyscall command = %llu\n", syscall_number);
		printf("\tInstruction pointer =\t0x%llx\n", regs->rip);
		printf("\tReturn pointer =\t0x%llx\n", regs->rcx);

		if (syscall_number == EXIT_SYSCALL ||
		    syscall_number == EXIT_GROUP_SYSCALL) {
			printf("Exiting.\n");
			ret = 1;
		}

		break;
	}
	case KVM_NITRO_EVENT_SYSRET:
		printf("Syscall exit id = %lx:\n", syscall);
		printf("\tReturn value = %llu\n", regs->rax);
		printf("\tInstruction pointer =\t0x%llx\n", regs->rip);
		break;
	case KVM_NITRO_EVENT_ERROR:
		fprintf(stderr, "Error event. Exiting.\n");
		ret = -1;
	default:
		fprintf(stderr, "Unknown event, %d. Exiting.\n", event);
		ret = -1;
	}

	/* Before stopping watching over the process, always tell KVM. */
	if (ret) {
		if (remove_process_trap(sregs->cr3)) {
			fprintf(stderr, "Failed to remove process 0x%llx\n",
				sregs->cr3);
			perror("");
			ret = -1;
		}
	}

	/*
	 * If the loop is not stopping because of an error,
	 * setup the search for the next process.
	 */
	if (ret == 1) {
		if (setup_search()) {
			fprintf(stderr, "Failed to return "
					"to process search.\n");
			ret = -1;
		}
	}

	return ret;
}

/* the state of the loop function that determines what to watch */
enum watch_state {
	/* Check all calls to open() to search for a process to watch. */
	SEARCH_PROC,
	/* Watch all system calls by one process. */
	WATCH_PROC
};

/* the current loop state */
static enum watch_state watch_state = SEARCH_PROC;

/*
 * Depending on the state, either look for a process to watch,
 * or watch a process.
 * @param ram		the RAM file
 * @param watched_file	the file whose opening
 *			indicates that a process should be watched.
 * @return		0 iff successful,
 *			-1 otherwise
 */
static int check_loop_event(struct ram_file *ram, const char *watched_file)
{
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	union event_data event_data;
	int event;
	int result;

	event = get_event(0, &event_data);

	if (event < 0) {
		perror("Failed to fetch event");
	}

	if (get_regs(0, &regs)) {
		fprintf(stderr, "Error getting general registers. Exiting.\n");
		return -1;
	}
	if (get_sregs(0, &sregs)) {
		fprintf(stderr, "Error getting system registers. Exiting.\n");
		return -1;
	}
	switch (watch_state) {
	case SEARCH_PROC:
		result = check_search_loop(ram, &regs, &sregs, event,
					   watched_file);
		if (result == 1) {
			watch_state = WATCH_PROC;
		} else if (result == -1) {
			return -1;
		}
		break;
	case WATCH_PROC:
		result = check_watch_loop(&regs, &sregs, event,
					  event_data.syscall);
		if (result == 1) {
			watch_state = SEARCH_PROC;
		} else if (result == -1) {
			return -1;
		}

		break;
	}

	return 0;
}

/*
 * Cleanup procedure to stop listening to the any system call,
 * and close the KVM file descriptor.
 * @param ram		the RAM file to destroy
 */
static void cleanup(struct ram_file *ram)
{
	unset_syscall_trap();

	close_kvm();

	if (destroy_ram_file(ram)) {
		perror("Failed to destroy the RAM file");
		/*
		 * Always retry closing the RAM file --
		 * The mmap-ed area will be unmapped anyways.
		 */
		if (ram->fd >= 0) {
			close(ram->fd);
		}

	}
}

/*
 * Perform all the steps,
 * now that the parameters have been read from the command line.
 * @param vm_pid	the PID of the virtual machine process
 * @param file_path	the path the the RAM file
 * @param watched_file	the file for which to watch for open() system calls
 * @return		0 iff successful
 */
static int track(pid_t vm_pid, const char *file_path, const char *watched_file)
{
	struct ram_file ram;
	int err;

	if (setup(vm_pid, file_path, &ram)) {
		return -1;
	}

	running = 1;
	signal(SIGINT, handle_stop);
	while (running) {
		int cont_err;

		err = check_loop_event(&ram, watched_file);

		cont_err = continue_vm(0);

		if (err) {
			break;
		}
		if (cont_err) {
			err = cont_err;
			break;
		}
	}

	cleanup(&ram);

	return err;
}

/*
 * The first argument after the program name
 * is the PID of the virtual machine process.
 */
#define QEMU_PID_ARG		1
/* The second argument after the program name is the path to the RAM file. */
#define MEMFILE_ARG		2
/* At least enter the PID of the virtual machine process and the RAM file. */
#define MIN_N_ARGS		(MEMFILE_ARG + 1)
/* Optionally enter the file to watch for open() system calls. */
#define WATCHED_FILE_ARG	3

/* If the watched file is not specified, watch the users' file by default. */
static const char *default_watched_file = "/etc/passwd";

int main(int argc, char *argv[])
{
	const char *vm_pid_str;
	pid_t vm_pid;
	const char *watched_file;

	if (argc < MIN_N_ARGS) {
		fprintf(stderr, "Usage: [qemu pid] [guest RAM filename] "
				"[optional target file name]\n");
		return -1;
	}

	vm_pid_str = argv[QEMU_PID_ARG];
	if (safe_atoi(&vm_pid, vm_pid_str)) {
		fprintf(stderr, "Invalid format for PID: \"%s\".\n",
			vm_pid_str);
	}

	if (argc > MIN_N_ARGS) {
		watched_file = argv[WATCHED_FILE_ARG];
	} else {
		watched_file = default_watched_file;
	}

	return track(vm_pid, argv[MEMFILE_ARG], watched_file);
}
