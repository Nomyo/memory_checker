#ifndef TRACK_HH
# define TRACK_HH

#include <map>
#include <elf.h>
#include <link.h>
#include <sys/auxv.h>
#include <sys/uio.h>

namespace Track
{
  struct tracker
  {
    pid_t child;
    ElfW(Phdr) *phdr = NULL;
    unsigned long phnum = 0;
    unsigned long phent = 0;
    struct r_debug *r_debug = NULL; /* map that stores the break point and library name */
    //std::map< std::string, std::map<void *, unsigned long>> m_break;

    void get_phdr();
    void get_r_debug_addr();
    int init_tracker();
  };
}
#endif /* !TRACK_HH */
