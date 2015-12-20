#ifndef SYSCALL_P
# define SYSCALL_P

#include <iostream>
#include <sys/reg.h>
#include <sys/ptrace.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/user.h>
#include <asm/unistd_64.h>

void p_syscall(int sys_num, struct user_regs_struct regs,
               pid_t child);
void p_sys_exit(int sys_num, int exit_value,
                pid_t child);
#endif /* !SYSCALL_P */
