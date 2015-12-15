#include "syscall_p.hh"

void p_syscall(int sys_num, struct user_regs_struct regs, pid_t child)
{
  if (sys_num == 59) /* execve */
    printf("[pid %d] execve () = %lld\n", child, regs.rax);
  else if (sys_num == 57) /* fork */
    printf("[pid %d] fork () = %lld\n", child, regs.rax);
  else if (sys_num == 58) /* vfork */
    printf("[pid %d] vfork () = %lld\n", child, regs.rax);
  else if (sys_num == 56) /* clone */
    printf("[pid %d] clone () = %lld\n", child, regs.rax);
  else if (sys_num == 9) /* mmap */
    printf("[pid %d] mmap () = 0x%llx\n", child, regs.rax);
  else if (sys_num == 25) /* mremap */
    printf("[pid %d] mremap () = 0x%llx\n", child, regs.rax);
  else if (sys_num == 10) /* mprotect */
    printf("[pid %d] mprotect () = 0x%llx\n", child, regs.rax);
  else if (sys_num == 11) /* munmap */
    printf("[pid %d] munmap () = %llx\n", child, regs.rax);
  else if (sys_num == 12) /* brk */
    printf("[pid %d] brk () = 0x%llx\n", child, regs.rax);
  else if (sys_num == 0) /* read */
    printf("[pid %d] read () = %lld\n", child, regs.rax);
  else if (sys_num == 1) /* write */
    printf("[pid %d] write () = %lld\n", child, regs.rax);
  else if (sys_num == 3) /* close */
    printf("[pid %d] close () = %lld\n", child, regs.rax);
  else if (sys_num == 4) /* stat */
    printf("[pid %d] stat () = %lld\n", child, regs.rax);
  else if (sys_num == 5) /* fstate */
    printf("[pid %d] fstat () = %lld\n", child, regs.rax);
  else if (sys_num == 6) /* lstat */
    printf("[pid %d] lstat () = %lld\n", child, regs.rax);
  else if (sys_num == 7) /* poll */
    printf("[pid %d] poll () = %lld\n", child, regs.rax);
  else if (sys_num == 8) /* lseek */
    printf("[pid %d] lseek () = %lld\n", child, regs.rax);
  else if (sys_num == 21) /* access */
    printf("[pid %d] access () = %lld\n", child, regs.rax);
  else if (sys_num == 16) /* ioctl */
    printf("[pid %d] ioctl () = %lld\n", child, regs.rax);
  else if (sys_num == 2) /* open */
    printf("[pid %d] open () = %lld\n", child, regs.rax);
  else if (sys_num == 78) /* getdents */
    printf("[pid %d] getdents () = %lld\n", child, regs.rax);
}

void p_sys_exit(int sys_num, int exit_value, pid_t child)
{
  if (sys_num == 60) /* exit */
    printf("[pid %d] exit () = %d\n", child, exit_value);
  if (sys_num == 231) /* exit_group */
    printf("[pid %d] exit_group () = %d\n", child, exit_value);
}
