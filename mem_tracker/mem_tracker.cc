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
#include <getopt.h>

void set_break(void *addr, pid_t pid)
{
  unsigned long ins = ptrace(PTRACE_PEEKDATA, pid, addr);
  ptrace(PTRACE_POKEDATA, pid, addr, (ins & 0xffffffffffffff00) | 0xcc);
}

void parsing_cmd_line(int argc, char **argv[], bool *b)
{
  if (strcmp((*argv)[1], "--preload") == 0)
  {
    if (argc < 4)
      {
        std::cerr << "too few arguments" << std::endl;
        exit(1);
      }
    else
    {
      (*argv) += 2;
      *b = true;
    }
  }
}

int in_child(char *argv[], bool load_lib)
{
  ptrace(PTRACE_TRACEME, 0, 0, 0);
  if (load_lib)
    setenv("LD_PRELOAD", argv[0], 1);
  return execvp(argv[1], argv);  
}

int main(int argc, char *argv[])
{
  if (argc < 2)
  {
    std::cerr << "usage: " << argv[0] << " arg\n";
    exit(1);
  }
  bool load_lib = false;
  parsing_cmd_line(argc, &argv, &load_lib);
  pid_t child = fork();
  if (child == 0)
    in_child(argv, load_lib);
  struct H_rdebug::auxv_info tr;
  tr.r_debug = (struct r_debug *)malloc(sizeof (struct r_debug));
  int status;
  waitpid(child, &status, 0);
  ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
  tr.child = child;
  tr.init_tracker(); 

  /* From here r_debug is set */

  Tracker tracker(child, tr.r_debug->r_state, argv[0]);
  set_break((void *)tr.r_debug->r_brk, tr.child);
  tracker.init_break();
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
          tracker.update(tr.r_debug->r_map); // update breakpoints
        else
          tracker.set_state(tr.r_debug->r_state); /* get previous state */
      }
      else
      {
        if (tracker.check_reg(regs) == 0)
          if (tracker.treat_break(tr.r_debug->r_map, regs.rip - 1, regs) == 1)
            break;
      }
    }
  }
  free(tr.r_debug);
  return 0;
}
