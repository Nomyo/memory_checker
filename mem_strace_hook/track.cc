#include "track.hh"
#include <elf.h>
#include <sys/auxv.h>
#include <link.h>
#include <iostream>
#include <fstream>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include "tools.hh"

namespace Track
{
  void tracker::get_phdr()
  {
    std::ifstream file;
    std::string s = "/proc/";
    s += std::to_string(child) + "/auxv";
    file.open(s.c_str());
    if (file.is_open() == false)
      {
        std::cerr << "Couldn't open /proc/" << child << "/auxv\n";
        return;
      }
    ElfW(auxv_t) auxv;
    file.read(reinterpret_cast<char *>(&auxv), sizeof (auxv));
    ElfW(auxv_t) *auxv_ptr = &auxv;
    while (auxv_ptr->a_type)
      {
        if (auxv_ptr->a_type == AT_PHDR)
          phdr = reinterpret_cast<ElfW(Phdr) *>(auxv_ptr->a_un.a_val);
        if (auxv_ptr->a_type == AT_PHNUM)
          phnum = auxv_ptr->a_un.a_val;
        if (auxv_ptr->a_type == AT_PHENT)
          phent = auxv_ptr->a_un.a_val;
        file.read(reinterpret_cast<char *>(&auxv), sizeof (auxv));
        if (!file.good())
          break;
        auxv_ptr = &auxv;
      }
    if (!phdr || !phnum)
      std::cerr << "No program header found \n";
    file.close();
  }

  void tracker::get_r_debug_addr()
  {
    struct r_debug *r_child;
    ElfW(Phdr) *ite = phdr;
    struct iovec local[1];
    struct iovec remote[1];
    char buf[512] = { 0 };
    local[0].iov_base = buf;
    local[0].iov_len = sizeof (ElfW(Phdr));
    for (unsigned i = 0; i < phnum; i++, ite++)
      {
        remote[0].iov_base = ite;
        remote[0].iov_len = sizeof (ElfW(Phdr));
        process_vm_readv(child, local, 1, remote, 1, 0);
        if (reinterpret_cast<ElfW(Phdr) *>(local[0].iov_base)->p_type == PT_DYNAMIC)
          {
            ite = reinterpret_cast<ElfW(Phdr) *>(local[0].iov_base);
            break;
          }
      }
    if (ite->p_type != PT_DYNAMIC)
      std::cerr << "No dynamic segment found" << std::endl;
    ElfW(Addr) pt_dynamic = reinterpret_cast<ElfW(Addr)>(ite->p_vaddr);
    local[0].iov_len = sizeof (ElfW(Dyn));
    do
      {
        while (true)
          {
            remote[0].iov_base = (void *)pt_dynamic;
            remote[0].iov_len = sizeof (ElfW(Dyn));
            process_vm_readv(child, local, 1, remote, 1, 0);
            if (reinterpret_cast<ElfW(Dyn) *>(local[0].iov_base)->d_tag == DT_DEBUG)
              {
                r_child = reinterpret_cast<struct r_debug *>
                  (reinterpret_cast<ElfW(Dyn) *>(local[0].iov_base)->d_un.d_ptr);
                break;
              }
            if (reinterpret_cast<ElfW(Dyn) *>(local[0].iov_base)->d_tag == DT_NULL)
              break;
            pt_dynamic += sizeof (ElfW(Dyn));
          }
        if (r_child == 0)
          {
            ptrace(PTRACE_SINGLESTEP, child, 0, 0);
            waitpid(child, 0, 0);
          }
        else
          {
            Tools::read_from_pid(child, sizeof (struct r_debug), this->r_debug, r_child);
            break;
          }
      }
    while (true);
  }

  int tracker::init_tracker()
  {
    get_phdr();
    if (!phdr || !phnum)
      return 1; /* */
    get_r_debug_addr();
    if (!r_debug)
      return -1;
    return 0;
  }
}
