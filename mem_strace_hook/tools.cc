#include "tools.hh"

namespace Tools
{

  ssize_t read_from_pid(pid_t pid, size_t size, void *buff, void *addr)
  {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buff;
    local[0].iov_len = size;
    remote[0].iov_base = addr;
    remote[0].iov_len = size;
    return process_vm_readv(pid, local, 1, remote, 1, 0);
  }

  ssize_t write_to_pid(pid_t pid, size_t size, void *buff, void *addr)
  {
    struct iovec local[1];
    struct iovec remote[1];
    local[0].iov_base = buff;
    local[0].iov_len = size;
    remote[0].iov_base = addr;
    remote[0].iov_len = size;
    return process_vm_writev(pid, local, 1, remote, 1, 0);
  }

  // make name to points to l_name field of the link_map structure 
  ssize_t get_load_obj_name(pid_t pid, struct link_map *l_map, char *name)
  {
    struct link_map in_child;
    read_from_pid(pid, sizeof (struct link_map), &in_child, l_map);
    return read_from_pid(pid, sizeof (char) * 512, name, in_child.l_name);
  }

  // return the l_next of link_map structure 
  struct link_map *get_load_obj_next(pid_t pid, struct link_map *l_map)
  {
    struct link_map in_child;
    read_from_pid(pid, sizeof (struct link_map), &in_child, l_map);
    l_map = in_child.l_next;
    return l_map;
  }
}
