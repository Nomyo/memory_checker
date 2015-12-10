#include "track.hh"
#include <elf.h>
#include <sys/auxv.h>
#include <link.h>
#include <iostream>

namespace Track
{
  void *get_phdr(pid_t child)
  {
    child = child;
    return NULL;
  }

  struct r_debug *get_r_debug_addr(pid_t child)
  {
    get_phdr(child);
    ElfW(Phdr) *phdr = reinterpret_cast<ElfW(Phdr) *>(getauxval(AT_PHDR)); /* to fix */
    unsigned nb_phdr = getauxval(AT_PHNUM);
    for (unsigned i = 0; i < nb_phdr; i++, phdr++)
      {
        if (phdr->p_type == PT_DYNAMIC)
          break;
      }
    if (phdr->p_type != PT_DYNAMIC)
      std::cerr << "No dynamic segment found" << std::endl;
    ElfW(Dyn) *dynamic = reinterpret_cast<ElfW(Dyn) *>(phdr->p_vaddr);
    struct r_debug *r_debug = NULL;
    for (; dynamic->d_tag != DT_DEBUG; dynamic++);
    r_debug = reinterpret_cast<struct r_debug *>(dynamic->d_un.d_ptr);
    return r_debug;
  }
}
