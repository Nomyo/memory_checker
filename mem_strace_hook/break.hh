#ifndef BREAK_HH
# define BREAK_HH

#include <map>
#include <unistd.h>
#include <sys/ptrace.h>
#include <iostream>

class Break
{
public:
  using pair_name_map = std::pair<char *, std::map<void *, unsigned long>>;

  Break();
  Break(pid_t pid);
  ~Break();
  void add_break(void *addr, char *l_name);
  void rem_break(void *addr, char *l_name);
  void print_breaks();
  void set_pid(pid_t pid);
  pid_t get_pid();
  void rem_loadobj(char *l_name);
private:
  std::map<std::string, std::map<void *, unsigned long>> mbreak_;
  pid_t pid_;
};

#endif /* !BREAK_HH */
