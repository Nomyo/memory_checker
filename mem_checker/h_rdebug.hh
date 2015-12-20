#ifndef H_RDEBUG_HH
# define H_RDEBUG_H

#include <map>
#include <elf.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/uio.h>

namespace H_rdebug
{
  struct auxv_info
  {
    pid_t child;
    ElfW(Phdr) *phdr = NULL;
    unsigned long phnum = 0;
    unsigned long phent = 0;
    struct r_debug *r_debug = NULL; /* map that stores the break point and library name */

    void get_phdr();
    void get_r_debug_addr();
    int init_tracker();
  };
}
#endif /* !H_RDEBUG_HH */
