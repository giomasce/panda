
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

const int PAGE_LEN = 1 << 12;
static inline target_ulong get_page(target_ulong addr) {
  target_ulong mask = ~((target_ulong) PAGE_LEN - 1);
  return addr & mask;
}

static inline hash64_t hash_page(CPUState *env, target_ulong addr) {
  uint8_t buf[PAGE_LEN];
  int res = panda_virtual_memory_rw(env, get_page(addr), buf, PAGE_LEN, 0);
  assert(res == 0);
  return xxhash< 64 >(buf, PAGE_LEN);
}

int before_block_exec_call(CPUState *env, TranslationBlock *tb) {
  //CPUArchState *cpu_env = (CPUArchState *)env->env_ptr;
  target_ulong pc = panda_current_pc(env);
  auto digest = hash_page(env, pc);
  printf("PC = %x, TB.pc = %x, TB.size = %d, page = %x, digest=%lx                \r", pc, tb->pc, tb->size, get_page(pc), digest);
  auto it = hashes.find(digest);
  if (it != hashes.end()) {
    printf("Found!\n");
  }
  return 0;
}

void read_hashes(const string &filename) {
  ifstream fin(filename);
  string line;
  while (getline(fin, line)) {
    size_t pos = line.find(':');
    hash64_t digest = strtoul(line.substr(0, pos).c_str(), NULL, 16);
    size_t pos2 = line.find(':', pos+1);
    size_t offset = strtoul(line.substr(pos+1, pos2).c_str(), NULL, 10);
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
