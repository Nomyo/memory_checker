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



///////////////////// TESTTTTTT ///////////////////////////////



void Break::get_shdr(ElfW(Ehdr) *elf_addr)
{
  int shnum =

}

void Break::load_lo(struct link_map *l_map)
{
  char name[512];
  ElfW(Ehdr) *elf;
  l_map = Tools::get_load_obj_next(pid_, l_map); // Bypass first l_map
  while (l_map)
    {
      Tools::get_load_obj_name(pid_, l_map, name);
      printf("Lib name :%s \n", name);
      int file = open(name, O_RDONLY);
      if (file == -1)
        {
          std::cerr << "Couldn't open " << name << " file" << std::endl;
          break;
        }
      struct stat s;
      if (fstat(file, &s) == -1)
        {
          std::cerr << "Couldn't open " << name << " file" << std::endl;
          break;
        }
      elf = (ElfW(Ehdr) *)mmap(0, s.st_size, PROT_READ, MAP_SHARED, file, 0); /* mapp the lib*/
      get_shdr(elf);
      munmap(elf, s.st_size);
      l_map = Tools::get_load_obj_next(pid_, l_map);
    }
}


////////////////////////////////////////////////////////////////

void Break::update(struct link_map *l_map)
{
  l_map = l_map;

  if (p_state_ == r_debug::RT_ADD)
    {
      load_lo(l_map);
      //      print_lib_name(l_map); /* should add all new load object */
    }
  else if (p_state_ == r_debug::RT_DELETE)
    rem_loadobj(l_map);
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

void Break::rem_loadobj(struct link_map *l_map)
{
  struct link_map *head = l_map;
  char name[512];
  for (auto const &i : mbreak_)
    {
      while (l_map)
        {
          Tools::get_load_obj_name(pid_, l_map, name);
          if (strcmp(name, i.first) == 0)
            break;
          Tools::get_load_obj_next(pid_, l_map);
        }
      if (!l_map)
        {
          mbreak_.erase(i.first);
          break;
        }
      else
        l_map = head;
    }
}

void Break::rem_break(void *addr, char *l_name)
{
  if (mbreak_[l_name].find(addr) != mbreak_[l_name].end())
    return;
  unsigned ins = mbreak_[l_name][addr];
  mbreak_[l_name].erase(addr);
  ptrace(PTRACE_POKEDATA, addr, ins); /* replace rip ? */
}

void Break::print_lib_name(struct link_map *l_map)
{
  char name[512];
  l_map = Tools::get_load_obj_next(pid_, l_map);
  while (l_map)
    {
      Tools::get_load_obj_name(pid_, l_map, name);
      printf("Lib name :%s \n", name);
      l_map = Tools::get_load_obj_next(pid_, l_map);
    }
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
