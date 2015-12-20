#ifndef TOOLS_HH
# define TOOLS_HH

#include <sys/uio.h>
#include <elf.h>
#include <unistd.h>
#include <link.h>
#include <string.h>


namespace Tools
{
  ssize_t read_from_pid(pid_t pid, size_t size, void *buff, void *addr);
  ssize_t write_to_pid(pid_t pid, size_t size, void *buff, void *addr);

  ssize_t get_load_obj_name(pid_t pid, struct link_map *l_map, char *name);
  struct link_map *get_load_obj_next(pid_t pid, struct link_map *l_map);
}

#endif /* !TOOLS_HH */
