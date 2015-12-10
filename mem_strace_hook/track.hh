#include <map>

namespace Track
{
  struct tracker
  {
    pid_t child;
    struct r_debug *r_debug;
    std::map<void *, unsigned long> map; /* map that stores the break point */
  };

  struct r_debug *get_r_debug_addr(pid_t child)
  {
    //int status;
    child = child;
    /*  waitpid(child, &status, 0);
  ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESYSGOOD
  | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE);*/
    ElfW(Phdr) *phdr = reinterpret_cast<ElfW(Phdr) *>(getauxval(AT_PHDR)); /* to fix */
    unsigned nb_phdr = getauxval(AT_PHNUM);
    for (unsigned i = 0; i < nb_phdr; i++, phdr++)
      {
        if (phdr->p_type == PT_DYNAMIC)
          {
            printf("a_phdr = 0x%x\n", (unsigned int)phdr->p_vaddr);
            break;
          }
      }
    ElfW(Dyn) *dynamic = reinterpret_cast<ElfW(Dyn) *>(phdr->p_vaddr);
    struct r_debug *r_debug = NULL;
    for (; dynamic->d_tag != DT_DEBUG; dynamic++);
    r_debug = reinterpret_cast<struct r_debug *>(dynamic->d_un.d_ptr);
    printf("version = %d\n", r_debug->r_version);
    return r_debug;
  }
}
