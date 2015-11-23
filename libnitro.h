#ifndef KFUNCS_H_
#define KFUNCS_H_

#include <linux/types.h>
#include <linux/kvm.h>
#include "nitro.h"

#include <stdlib.h>

int init_kvm();
int close_kvm();

//kvm functions
int get_num_vms();
int attach_vm(pid_t);

int set_syscall_trap(int*,int);
/*
 * Watch all system calls.
 * @return	0 iff successful, -1 otherwise
 */
int set_all_syscall_trap();
int unset_syscall_trap();
/*
 * Start watching a process.
 * @param process	the identifier for the process to watch
 * @return		0 on success,
 *			-1 with errno set to
 *				ENOMEM if no space could be allocated
 *					for the new process,
 *				EINVAL if the process is already watched
 */
int add_process_trap(ulong process);
/*
 * Stop watching a process.
 * @param process	the identifier for the process to unwatch
 * @return		0 on success,
 *			-1 with errno set to
 *				EINVAL if the process was not previously watched
 */
int remove_process_trap(ulong process);

//vm functions
int attach_vcpus();

//vcpu functions
int get_regs(int, struct kvm_regs*);
int get_sregs(int, struct kvm_sregs*);
int get_event(int, union event_data*);
int continue_vm(int);

//memory access definitions
/* reader-friendly typedef for guest address */
typedef __u64 addr_t;

/* the memory-mapped file containing the guest memory */
struct ram_file {
  /* the file descriptor of the guest memory file. -1 if invalid */
  int fd;
  /* the total number of bytes in guest memory. 0 if invalid */
  size_t size;
  /* the memory-mapped file data. NULL if invalid */
  void *ram;
};

//memory access functions
/*
 * Open the guest RAM file, and map it to memory.
 * @param to_init	the output struct, which will be initialized
 * @param file_path	the path to the RAM file to open and map
 * @return		0 iff successful,
 *			-1 otherwise,
 *				in which case all fields will be invalidated,
 *				and errno will be set by open or mmap
 */
int init_ram_file(struct ram_file *to_init, const char *file_path);
/*
 * Unmap and close the guest RAM file, and invalidate the fields.
 * @param to_destroy	the RAM file struct to destroy
 * @return		0 iff successful,
 *			-1 otherwise, and errno will be set by munmap or close,
 *				but only the fields that could not be destroyed
 *				are invalidated
 */
int destroy_ram_file(struct ram_file *to_destroy);
/*
 * Translate a virtual address to an address mapped to the RAM file.
 * @param vcpu_id		the ID of the VCPU ID used for the
 *				vcpu ioctl call
 * @param ram			the RAM file information used to
 *				calculate the file-mapped pointer
 * @param v_addr		the virtual address to translate
 * @param guest_phys_ptr	the output pointer
 * @return			0 iff successful,
 *				-1 if this function detected
 *					that the translation is invalid,
 *					or the address is too high,
 *					in which case errno is set to EFAULT,
 *				an error value by the ioctl call to KVM,
 *					if it failed, in which case
 *					ioctl sets errno.
 *				In both error cases, *guest_phys_ptr = NULL
 */
int translate_addr(int vcpu_id, struct ram_file *ram, addr_t v_addr,
		   void **guest_phys_ptr);
#endif //KFUNCS_H_
