
#include <unordered_map>
#include <unordered_set>
#include <iostream>
#include <fstream>

#include "panda/plugin.h"

#include "xxhash.hpp"

using namespace std;
using namespace xxh;

unordered_map< hash64_t, pair< string, size_t > > hashes;
unordered_set< hash64_t > multiple_hashes;

// These need to be extern "C" so that the ABI is compatible with
// QEMU/PANDA, which is written in C
extern "C" {
  bool init_plugin(void *);
  void uninit_plugin(void *);
}

const int MINIPAGE_LEN = 1 << 8;
static inline target_ulong get_page(target_ulong addr) {
  target_ulong mask = ~((target_ulong) MINIPAGE_LEN - 1);
  return addr & mask;
}

static inline hash64_t hash_page(CPUState *env, target_ulong addr) {
  uint8_t buf[MINIPAGE_LEN];
  int res = panda_virtual_memory_rw(env, get_page(addr), buf, MINIPAGE_LEN, 0);
  assert(res == 0);
  return xxhash< 64 >(buf, MINIPAGE_LEN);
}

int before_block_exec_call(CPUState *env, TranslationBlock *tb) {
  //CPUArchState *cpu_env = (CPUArchState *)env->env_ptr;
  target_ulong pc = panda_current_pc(env);
  auto digest = hash_page(env, pc);
  target_ulong page = get_page(pc);
  //target_ulong phys_page = panda_virt_to_phys(env, page);
  bool in_kernel = panda_in_kernel(env);
  target_ulong asid = panda_current_asid(env);
  auto it = hashes.find(digest);
  string filename = "<unk>";
  size_t filepos = 0;
  bool found = it != hashes.end();
  bool unique = true;
  if (found) {
    filename = it->second.first;
    filepos = it->second.second + (pc - page);
    unique = multiple_hashes.find(digest) == multiple_hashes.end();
  }
  if (pandalog) {
    Panda__LogEntry ple = PANDA__LOG_ENTRY__INIT;
    Panda__Where where = PANDA__WHERE__INIT;
    ple.where = &where;
    where.digest = digest;
    where.in_kernel = in_kernel;
    where.asid = asid;
    where.tb_size = tb->size;
    if (found) {
      where.filename = strdup(filename.c_str());
      where.has_pos = 1;
      where.pos = filepos;
      where.has_unique_digest = 1;
      where.unique_digest = unique;
    }
    pandalog_write_entry(&ple);
    free(where.filename);
  }
  //printf("PC = %x, TB.pc = %x, TB.size = %d, page = %x, phys page = %x, digest = %lx, file = %s, pos = %lx                                    \r", pc, tb->pc, tb->size, page, phys_page, digest, filename.c_str(), filepos);
  return 0;
}

void read_hashes(const string &filename) {
  ifstream fin(filename);
  string line;
  while (getline(fin, line)) {
    size_t pos = line.find(':');
    hash64_t digest = strtoul(line.substr(0, pos).c_str(), NULL, 16);
    size_t pos2 = line.find(':', pos+1);
    size_t offset = strtoul(line.substr(pos+1, pos2).c_str(), NULL, 16);
    string file = line.substr(pos2+1);

    bool res;
    tie(ignore, res) = hashes.insert(make_pair(digest, make_pair(file, offset)));
    if (!res) {
      multiple_hashes.insert(digest);
    }
  }
  cerr << "Found " << hashes.size() << " unique hashes, of which " << multiple_hashes.size() << " appearing more than once!" << endl;
}

bool init_plugin(void *self) {
  panda_cb pcb;
  read_hashes("hashes.txt");
  pcb.before_block_exec = before_block_exec_call;
  panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
  return true;
}

void uninit_plugin(void *self) {
}
