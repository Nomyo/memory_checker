#include <sys/auxv.h>
#include <elf.h>
#include <stdio.h>
#include <iostream>
#include <sys/ptrace.h>
#include <unistd.h>
#include <sys/wait.h>
#include <link.h>
#include "track.hh"

extern ElfW(Dyn) _DYNAMIC[];

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
  struct Track::tracker tr;
  int status;
  waitpid(child, &status, 0);
  ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD);
  tr.child = child;
  tr.init_tracker();
  while (true)
    {
      ptrace(PTRACE_SINGLESTEP, child, 0, 0);
      waitpid(child, &status, 0);
      if (WIFSTOPPED(status) && WSTOPSIG(status) & 0x80)
        return 0;
      if (WIFEXITED(status))
        return 1;
    }

  return 0;
}
