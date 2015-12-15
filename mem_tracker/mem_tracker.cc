#include <sys/auxv.h>
#include <elf.h>
#include <stdio.h>
#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <link.h>
#include "track.hh"
#include "h_rdebug.hh"
#include "tools.hh"
#include <sys/types.h>
#include <features.h>
#include <dlfcn.h>
#include <sys/reg.h>
#include <sys/user.h>

void set_break(void *addr, pid_t pid)
{
  unsigned long ins = ptrace(PTRACE_PEEKDATA, pid, addr);
  ptrace(PTRACE_POKEDATA, pid, addr, (ins & 0xffffffffffffff00) | 0xcc);
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    std::cerr << "usage: " << argv[0] << " arg\n";
    exit(1);
  }
  pid_t child = fork();
  argv++;
  if (child == 0)
  {
    ptrace(PTRACE_TRACEME, 0, 0, 0);
    return execvp(argv[0], argv);
  }
  struct H_rdebug::auxv_info tr;
  tr.r_debug = (struct r_debug *)malloc(sizeof (struct r_debug));
  int status;
  waitpid(child, &status, 0);
  ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
  tr.child = child;
  tr.init_tracker(); /* From here r_debug is set */
  Tracker l_break(child, tr.r_debug->r_state, argv[0]);
  set_break((void *)tr.r_debug->r_brk, tr.child);
  l_break.init_break();
  struct user_regs_struct regs;
  while (true)
  {
    ptrace(PTRACE_CONT, child, 0, 0);
    waitpid(child, &status, 0);
    if (WIFEXITED(status))
    {
      free(tr.r_debug);
      printf("++++++ exited with %d ++++++\n", WIFEXITED(status));
      return 0;
    }
    tr.get_r_debug_addr(); /* update r_debug */
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) /* Program breaks */
    {
      ptrace(PTRACE_GETREGS, child, NULL, &regs);
      if ((unsigned long )regs.rip - 1 == (unsigned long)tr.r_debug->r_brk)
      {
        if (tr.r_debug->r_state == r_debug::RT_CONSISTENT) /* add or del lib*/
          l_break.update(tr.r_debug->r_map); // update breakpoints
        else
          l_break.set_state(tr.r_debug->r_state); /* get previous state */
      }
      else
      {
        if (l_break.treat_break(tr.r_debug->r_map, regs.rip - 1, regs) == 1)
          break;
      }
    }
  }
  free(tr.r_debug);
  return 0;
}
