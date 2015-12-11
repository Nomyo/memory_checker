#ifndef TRACK_HH
# define TRACK_HH

#include <map>
#include <elf.h>
#include <link.h>
#include <sys/auxv.h>

namespace Track
{
  struct tracker
  {
    pid_t child;
    ElfW(Phdr) *phdr = NULL;
    unsigned long phnum = 0;
    struct r_debug *r_debug = NULL; /* map that stores the break point and library name */
    std::map<std::map<void *, unsigned long>, std::string> map;
    void get_phdr(pid_t child);
    void get_r_debug_addr();
    int init_tracker(pid_t child);
  };
}
#endif /* !TRACK_HH */
