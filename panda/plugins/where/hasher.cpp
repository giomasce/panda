
#include <fstream>
#include <iostream>
#include <iomanip>

#include <cstring>

#include "xxhash.hpp"

using namespace std;
using namespace xxh;

void hash_file(const char *filename, int increment, int offset = 0) {
  vector< char > buf(increment);
  ifstream fin(filename);
  fin.seekg(offset);
  while (fin) {
    bzero(buf.data(), increment);
    fin.read(buf.data(), increment);
    hash64_t digest = xxhash< 64 >(buf, increment);
    cout << setfill('0') << setw(16) << hex << digest << ":" << offset << ":" << filename << endl;
    offset += increment;
  }
}

int main(int argc, char *argv[]) {
  for (int i = 1; i < argc; i++) {
    hash_file(argv[i], 0x100);
  }
  return 0;
}
