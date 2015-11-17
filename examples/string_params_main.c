/*
 * an example of memory access using string references to the pathname parameter
 * in the open() system call
 * When running qemu, make sure that the options for using and sharing RAM files
 * are enabled.
 * In particular,
 * use the version of QEMU from https://github.com/pfohjo/qemu.git,
 * with the options: -mem-path [hugetlbfs directory] -mem-prealloc
 * (for more information about using hugetlbfs, read
 * http://linux-kvm.com/content/get-performance-boost-backing-your-kvm-guest-hugetlbfs).
 * Run this program using
 * "[parent directory of this program]/string_params [pid of virtual machine] [hugetlbfs directory]/qemu_back_mem.pc.ram.[some letters and numbers]"
 */
#include <user_utils.h>

#include <libnitro.h>

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

/* the system call number for open() in Linux for x86-64 */
static int open_syscall[1] = {2};

/*
 * Set up the connection to KVM, and open and map the RAM file.
 * @param vm_pid	the PID of the virtual machine process
 * @param file_path	the path the the RAM file
 * @param ram		the state of the RAM file,
 *			used throughout the execution of this program
 * @return		0 iff successful
 */
static int setup(pid_t vm_pid, const char *file_path, struct ram_file *ram)
{
	int n_vcpus;
	int vmfd;
	int err;

	/* Open and map the RAM file. */
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

	if ((err = set_syscall_trap(open_syscall, 1))) {
		fprintf(stderr, "Unable to listen for system calls");
		goto SET_SYSCALL_TRAP_FAIL;
	}

	return 0;
SET_SYSCALL_TRAP_FAIL:
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
 * Fetch a string from the guest memory.
 * @param v_addr	the virtual address of the string
 * @param ram		the RAM file
 * @return		a copy of the string on success,
 *				which will need to be freed;
 *			NULL otherwise
 *				(so you can also pass it to free without error)
 */
static char *
get_string(addr_t v_addr, struct ram_file *ram)
{
	void *guest_phys_ptr;

	if (translate_addr(0, ram, v_addr, &guest_phys_ptr)) {
		fprintf(stderr, "Failed to translate string pointer 0x%llx.\n",
			v_addr);
		return NULL;
	}

	printf("Translated string address 0x%llx -> 0x%lx\n", v_addr,
	       (unsigned long) (guest_phys_ptr - ram->ram));

	return strdup((char *) guest_phys_ptr);
}

/*
 * Report on a single open() syscall event in the loop.
 * @param ram	the RAM file
 * @return	0 iff successful
 */
static int check_loop_event(struct ram_file *ram)
{
	struct kvm_regs regs;
	struct kvm_sregs sregs;
	char *pathname;
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
		pathname = get_string(regs.rdi, ram);
		printf("Entry to open() by cr3 =\t0x%llx, id = %lx:\n",
		       sregs.cr3, event_data.syscall);
		printf("\tpathname = \"%s\" (at 0x%llx)\n\tflags = 0x%llx\n",
		       pathname, regs.rdi, regs.rsi);
		free(pathname);
		break;
	case KVM_NITRO_EVENT_SYSRET:
		printf("Exit from open() by cr3 =\t0x%llx, id = %lx:\n",
		       sregs.cr3, event_data.syscall);
		printf("\tfd = %llu\n", regs.rax);
		break;
	case KVM_NITRO_EVENT_ERROR:
		fprintf(stderr, "Error event. Exiting.\n");
		return -1;
	}

	return 0;
}

/*
 * Cleanup procedure to stop listening to the open() system call,
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
 * @return		0 iff successful
 */
static int track(pid_t vm_pid, const char *file_path)
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

		err = check_loop_event(&ram);

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
#define QEMU_PID_ARG	1
/* The second argument after the program name is the path to the RAM file. */
#define MEMFILE_ARG	2

int main(int argc, char *argv[])
{
	const char *vm_pid_str;
	pid_t vm_pid;

	if (argc <= MEMFILE_ARG) {
		fprintf(stderr, "Usage: [qemu pid] [guest RAM filename]\n");
		return -1;
	}

	vm_pid_str = argv[QEMU_PID_ARG];
	if (safe_atoi(&vm_pid, vm_pid_str)) {
		fprintf(stderr, "Invalid format for PID: \"%s\".\n",
			vm_pid_str);
	}

	return track(vm_pid, argv[MEMFILE_ARG]);
}
