
#include <fstream>
#include <iostream>
#include <iomanip>

#include <cstring>

#include "xxhash.hpp"

using namespace std;
using namespace xxh;

const int PAGE_LEN = 1 << 12;

void hash_file(char *filename) {
  ifstream fin(filename);
  int offset = 0;
  while (fin) {
    char buf[PAGE_LEN];
    bzero(buf, PAGE_LEN);
    fin.read(buf, PAGE_LEN);
    hash64_t digest = xxhash< 64 >(buf, PAGE_LEN);
    cout << setfill('0') << setw(16) << hex << digest << ":" << dec << offset << ":" << filename << endl;
    offset += PAGE_LEN;
  }
}

int main(int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    hash_file(argv[i]);
  }
  return 0;
}
