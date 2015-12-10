#include "syscall_p.hh"

void p_syscall(int sys_num, struct user_regs_struct regs, pid_t child)
{
  if (sys_num == 59) /* execve */
    printf("[pid %d] execve () = %lld\n", child, regs.rax);
  if (sys_num == 57) /* fork */
    printf("[pid %d] fork () = %lld\n", child, regs.rax);
  if (sys_num == 58) /* vfork */
    printf("[pid %d] vfork () = %lld\n", child, regs.rax);
  if (sys_num == 56) /* clone */
    printf("[pid %d] clone () = %lld\n", child, regs.rax);
  if (sys_num == 9) /* mmap */
    printf("[pid %d] mmap () = 0x%llx\n", child, regs.rax);
  if (sys_num == 25) /* mremap */
    printf("[pid %d] mremap () = 0x%llx\n", child, regs.rax);
  if (sys_num == 10) /* mprotect */
    printf("[pid %d] mprotect () = 0x%llx\n", child, regs.rax);
  if (sys_num == 11) /* munmap */
    printf("[pid %d] munmap () = 0x%llx\n", child, regs.rax);
  if (sys_num == 12) /* brk */
    printf("[pid %d] brk () = 0x%llx\n", child, regs.rax);
}

void p_sys_exit(int sys_num, int exit_value, pid_t child)
{
  if (sys_num == 60) /* exit */
    printf("[pid %d] exit () = %d\n", child, exit_value);
  if (sys_num == 231) /* exit_group */
    printf("[pid %d] exit_group () = %d\n", child, exit_value);
}
