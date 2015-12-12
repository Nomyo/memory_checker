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

}
