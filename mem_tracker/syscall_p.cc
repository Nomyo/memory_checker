#include "syscall_p.hh"

void p_syscall(int sys_num, struct user_regs_struct regs, pid_t child)
{
  if (sys_num == 9) /* mmap */
    printf("[pid %d] mmap { addr = 0x%llx, len = 0x%llx, prot = %lld }\n",
           child, regs.rax, regs.rsi, regs.rdx);
  else if (sys_num == 25) /* mremap */
    printf("[pid %d] mremap { addr = 0x%llx, len = 0x%llx, prot = %lld\n",
           child, regs.rdi, regs.rsi, regs.rdx);
  else if (sys_num == 10) /* mprotect */
    printf("[pid %d] mprotect () = 0x%llx\n", child, regs.rax);
  else if (sys_num == 11) /* munmap */
    printf("[pid %d] munmap { addr =  0x%llx, len = 0x%llx, prot = %lld }\n",
           child, regs.rdi, regs.rsi, regs.rdx);
  else if (sys_num == 12) /* brk */
    printf("[pid %d] brk () = 0x%llx\n", child, regs.rax);
}

void p_sys_exit(int sys_num, int exit_value)
{
  if (sys_num == 60) /* exit */
    printf("exit () = %d\n", exit_value);
  if (sys_num == 231) /* exit_group */
    printf("exit_group () = %d\n", exit_value);
}
