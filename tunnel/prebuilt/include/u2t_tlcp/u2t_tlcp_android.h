#include <cstdarg>
#include <cstdint>
#include <cstdlib>
#include <ostream>
#include <new>

struct COptions {
  const char *tcp_addr;
  const char *udp_addr;
  const char *chain_ca_cert;
  const char *log_level;
  const char *virtual_network;
};

extern "C" {

uint64_t multiply(uint64_t left, uint64_t right);

char *run(const COptions *c_opts);

void free_c_string(char *ptr);

}  // extern "C"
