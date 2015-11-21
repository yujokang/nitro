#include <fcntl.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>

#include "libnitro.h"
#include "nitro.h"

#define KVM_NODE "/dev/kvm"

int kvm_fd;
int kvm_vmfd;
struct nitro_vcpus vcpus;

int kvm_ioctl(int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(kvm_fd, type, arg);
    if (ret == -1)
        ret = -errno;

    return ret;
}

int kvm_vm_ioctl(int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(kvm_vmfd, type, arg);
    if (ret == -1)
        ret = -errno;

    return ret;
}

int kvm_vcpu_ioctl(int vcpu_fd,int type, ...)
{
    int ret;
    void *arg;
    va_list ap;

    va_start(ap, type);
    arg = va_arg(ap, void *);
    va_end(ap);

    ret = ioctl(vcpu_fd, type, arg);
    if (ret == -1)
        ret = -errno;

    return ret;
}

int init_kvm(){
  kvm_vmfd = 0;
  memset(&vcpus,0,sizeof(struct nitro_vcpus));
  
  if((kvm_fd = open(KVM_NODE, O_RDWR)) < 0){
    kvm_fd = 0;
    return -errno;
  }
  
  return 0;
}

int close_kvm(){
  int i;
  
  for(i=0;i<vcpus.num_vcpus;i++){
    if(vcpus.fds[i]>0)
      close(vcpus.fds[i]);
  }
  
  if(kvm_vmfd>0){
    close(kvm_vmfd);
  }
  
  close(kvm_fd);
  return 0;
}




int get_num_vms(){
  return kvm_ioctl(KVM_NITRO_NUM_VMS);
}

int attach_vm(pid_t creator){
  int rv=0;
  
  kvm_vmfd = kvm_ioctl(KVM_NITRO_ATTACH_VM,&creator);
  
  if(kvm_vmfd<0)
    rv = kvm_vmfd;
  return rv;
}

int attach_vcpus(){
  int rv;
  
  rv = kvm_vm_ioctl(KVM_NITRO_ATTACH_VCPUS,&vcpus);
  
  if(rv == 0)
    rv = vcpus.num_vcpus;
  
  return rv;
}


int set_syscall_trap(int *sc, int sc_size){
  struct nitro_syscall_trap sct;
  
  sct.size = sc_size;
  sct.syscalls = sc;
  
  return kvm_vm_ioctl(KVM_NITRO_SET_SYSCALL_TRAP,&sct);
}

int set_all_syscall_trap(){
  return kvm_vm_ioctl(KVM_NITRO_SET_ALL_SYSCALL_TRAP);
}

int unset_syscall_trap(){
  return kvm_vm_ioctl(KVM_NITRO_UNSET_SYSCALL_TRAP);
}

int get_regs(int vcpu_id, struct kvm_regs *regs){
  if(vcpu_id >= vcpus.num_vcpus)
    return -1;
  
  return kvm_vcpu_ioctl(vcpus.fds[vcpu_id],KVM_NITRO_GET_REGS,regs);
}

int get_sregs(int vcpu_id, struct kvm_sregs *sregs){
  if(vcpu_id >= vcpus.num_vcpus)
    return -1;
  
  return kvm_vcpu_ioctl(vcpus.fds[vcpu_id],KVM_NITRO_GET_SREGS,sregs);
}

int get_event(int vcpu_id, union event_data *ed){
  if(vcpu_id >= vcpus.num_vcpus)
    return -1;
  return kvm_vcpu_ioctl(vcpus.fds[vcpu_id],KVM_NITRO_GET_EVENT,ed);
}

int continue_vm(int vcpu_id){
  if(vcpu_id >= vcpus.num_vcpus)
    return -1;
  return kvm_vcpu_ioctl(vcpus.fds[vcpu_id],KVM_NITRO_CONTINUE);
}

/*
 * unsafe version of init_ram_file that does not invalidate
 * the fields of to_init on error.
 * @param to_init	the output struct, which will be initialized
 * @param file_path	the path to the RAM file to open and map
 * @return		0 iff successful,
 *			-1 otherwise,
 *				in which case errno will be set by open or mmap
 */
static int _init_ram_file(struct ram_file *to_init, const char *file_path)
{
  struct stat size_holder;
  int fd;
  void *ram;

  if (stat(file_path, &size_holder)) {
    return -1;
  }

  if ((fd = open(file_path, O_RDWR)) == -1) {
    return -1;
  }

  if ((ram = mmap(NULL, size_holder.st_size, PROT_READ | PROT_WRITE,
		  MAP_SHARED, fd, 0)) == NULL) {
    return -1;
  }

  to_init->fd = fd;
  to_init->size = size_holder.st_size;
  to_init->ram = ram;

  return 0;
}

int init_ram_file(struct ram_file *to_init, const char *file_path)
{
  int err;
  if ((err = _init_ram_file(to_init, file_path))) {
    to_init->fd = -1;
    to_init->size = 0;
    to_init->ram = NULL;
  }

  return err;
}

int destroy_ram_file(struct ram_file *to_destroy)
{
  int err = 0;
  if (munmap(to_destroy->ram, to_destroy->size)) {
    err = -1;
  } else {
    to_destroy->size = 0;
    to_destroy->ram = NULL;
  }

  if (close(to_destroy->fd)) {
    err = -1;
  } else {
    to_destroy->fd = -1;
  }

  return err;
}

/*
 * unsafe version of translate_addr
 * that does not invalidate *guest_phys_ptr on error
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
 */
int _translate_addr(int vcpu_id, struct ram_file *ram, addr_t v_addr,
		    void **guest_phys_ptr)
{
  struct kvm_translation translation;
  addr_t physical_address;
  int err;

  translation.linear_address = v_addr;

  if ((err = kvm_vcpu_ioctl(vcpus.fds[vcpu_id], KVM_NITRO_TRANSLATE,
			    &translation))) {
    return err;
  }

  if (!translation.valid) {
    errno = EFAULT;
    return -1;
  }

  physical_address = translation.physical_address;
  if (physical_address >= ram->size) {
    errno = EFAULT;
    return -1;
  }

  *guest_phys_ptr = ram->ram + physical_address;

  return 0;
}

int translate_addr(int vcpu_id, struct ram_file *ram, addr_t v_addr,
		   void **guest_phys_ptr)
{
  int err;

  if ((err = _translate_addr(vcpu_id, ram, v_addr, guest_phys_ptr))) {
    *guest_phys_ptr = NULL;
  }

  return err;
}
