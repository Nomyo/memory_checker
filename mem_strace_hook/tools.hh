#ifndef TOOLS_HH
# define TOOLS_HH

#include <sys/uio.h>
#include <elf.h>
#include <unistd.h>

namespace Tools
{
  ssize_t read_from_pid(pid_t pid, size_t size, char *buff, void *addr);
  ssize_t write_to_pid(pid_t pid, size_t size, char *buff, void *addr);
}

#endif /* !TOOLS_HH */
