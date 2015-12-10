#include <sys/ptrace.h>
#include <sys/reg.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <iostream>
#include <signal.h>
#include <sys/wait.h>
#include <sys/user.h>
#include "syscall_p.hh"
#include <errno.h>

int wait_syscall(pid_t child, int *status)
{
  while (true)
    {
      ptrace(PTRACE_SYSCALL, child , 0, 0); /* Continue child process */
      waitpid(child, status, 0);
      if (WIFSTOPPED(*status) && WSTOPSIG(*status) & 0x80)
        return 0;
      if (WIFEXITED(*status))
        return 1;
    }
}

int in_child(char **argv)
{
  ptrace(PTRACE_TRACEME, 0, 0, 0); /* child process can now be traced */
  kill(getpid(), SIGSTOP); /* give hand back to father */
  return execvp(argv[0], argv);
}

int trace_child(pid_t child)
{
  int status;
  waitpid(child, &status, 0);
  ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD
         | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);
  struct user_regs_struct regs;
  while (true)
    {
      if (wait_syscall(child, &status) != 0)
        {
          ptrace(PTRACE_GETREGS, child, NULL, &regs);
          p_sys_exit(regs.orig_rax, WEXITSTATUS(status), child);
          break;
        }
      ptrace(PTRACE_GETREGS, child, NULL, &regs);
      if (regs.rax != -ENOSYS) /* if not on entry */
      p_syscall(regs.orig_rax, regs, child);
    }
  return 0;
}


int main(int argc, char *argv[])
{
  if (argc < 2)
    {
      std::cerr << "usage: " << argv[0] << " arg\n";
      exit(1);
    }
  pid_t child = fork(); /* One process to execute the program */
  argv++;               /* and the other one to trace it */
  if (child == 0)
    return in_child(argv);
  else
    return trace_child(child);

  std::cout << argv[0] << "\n";
}
