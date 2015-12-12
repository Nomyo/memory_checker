#include "break.hh"

Break::Break()
  : mbreak_()
{}

Break::Break(pid_t pid, int state)
  : mbreak_()
  , pid_(pid)
  , p_state_(state)
{}

void Break::set_pid(pid_t pid)
{
  pid_ = pid;
}

pid_t Break::get_pid()
{
  return pid_;
}

Break::~Break() = default;

void Break::set_state(int state)
{
  p_state_ = state;
}

int Break::get_state()
{
  return p_state_;
}

void Break::update(struct link_map *l_map)
{
  l_map = l_map;
}

void Break::add_break(void *addr, char *l_name)
{
  if (mbreak_.find(l_name) == mbreak_.end()) /* unpatch loaded objects*/
    {
      mbreak_.insert(pair_name_map(l_name, std::map<void *, unsigned long>{}));
      unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, addr); /* get instruction */
      mbreak_[l_name].insert(std::pair<void *, unsigned long>(addr, ins)); /* store old ins */
      ptrace(PTRACE_POKEDATA, addr, (ins & 0xffffffffffffff00) | 0xcc); /* insert break point*/
    }
  else
    {
      if (mbreak_[l_name].find(addr) != mbreak_[l_name].end())
        return;
      else
        {
          mbreak_.insert(pair_name_map(l_name, std::map<void *, unsigned long>{}));
          unsigned long ins = ptrace(PTRACE_PEEKDATA, pid_, addr);
          mbreak_[l_name].insert(std::pair<void *, unsigned long>(addr, ins));
          ptrace(PTRACE_POKEDATA, addr, (ins & 0xffffffffffffff00) | 0xcc);
        }
    }
}

void Break::rem_loadobj(char *l_name)
{
  mbreak_.erase(l_name);
}

void Break::rem_break(void *addr, char *l_name)
{
  if (mbreak_[l_name].find(addr) != mbreak_[l_name].end())
    return;
  unsigned ins = mbreak_[l_name][addr];
  mbreak_[l_name].erase(addr);
  ptrace(PTRACE_POKEDATA, addr, ins); /* replace rip ? */
}

void Break::print_breaks()
{
  for (auto const &i : mbreak_)
    {
      std::cout << "In :" << i.first << std::endl;
      for (auto const &j : i.second)
        printf("\t 0x%lx with %ld\n", (unsigned long)j.first, j.second);
    }
}
