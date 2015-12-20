#include "syscall_p.hh"

void p_syscall(int sys_num, struct user_regs_struct regs, pid_t child)
{
  if (sys_num == __NR_execve) /* execve */
    printf("[pid %d] execve () = %lld\n", child, regs.rax);
  if (sys_num == __NR_fork) /* fork */
    printf("[pid %d] fork () = %lld\n", child, regs.rax);
  if (sys_num == __NR_vfork) /* vfork */
    printf("[pid %d] vfork () = %lld\n", child, regs.rax);
  if (sys_num == __NR_clone) /* clone */
    printf("[pid %d] clone () = %lld\n", child, regs.rax);
  if (sys_num == __NR_mmap) /* mmap */
    printf("[pid %d] mmap () = 0x%llx\n", child, regs.rax);
  if (sys_num == __NR_mremap) /* mremap */
    printf("[pid %d] mremap () = 0x%llx\n", child, regs.rax);
  if (sys_num == __NR_mprotect) /* mprotect */
    printf("[pid %d] mprotect () = 0x%llx\n", child, regs.rax);
  if (sys_num == __NR_munmap) /* munmap */
    printf("[pid %d] munmap () = 0x%llx\n", child, regs.rax);
  if (sys_num == __NR_brk) /* brk */
    printf("[pid %d] brk () = 0x%llx\n", child, regs.rax);
}

void p_sys_exit(int sys_num, int exit_value, pid_t child)
{
  if (sys_num == __NR_exit) /* exit */
    printf("[pid %d] exit () = %d\n", child, exit_value);
  if (sys_num == __NR_exit_group) /* exit_group */
    printf("[pid %d] exit_group () = %d\n", child, exit_value);
}
