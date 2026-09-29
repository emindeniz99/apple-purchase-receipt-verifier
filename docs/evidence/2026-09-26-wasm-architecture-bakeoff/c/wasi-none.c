// Spike only (Route C: freestanding core module). Linked into a
// wasm32-wasip1 build, this file DEFINES every WASI preview-1 function that
// wasi-libc would otherwise import, so wasm-ld resolves them inside the
// module and the finished .wasm imports no "wasi_snapshot_preview1" at all.
//
// wasi-libc calls each WASI function through a symbol named
// __imported_wasi_snapshot_preview1_<name> that carries the import
// attributes (libc-bottom-half/sources/__wasilibc_real.c). A definition of
// that symbol here wins over the import. Nothing in the security library or
// in wasi-libc is patched; this is a link-time host, not a runtime.
//
// What the module can still reach, and only through these two imports:
//   aprv.clock_now_ms  : wall clock, ms since 1970 (Date.now()).
//   aprv.random_get    : only with -DAPRV_HOST_RANDOM (OpenSSL: EC blinding);
//                        otherwise random_get traps (AWS-LC never calls it).
// Everything else: no environment, no arguments, no preopened directory,
// no file, no socket. File calls answer EBADF/ENOSYS; exit traps.
#include <stdint.h>

#define ERRNO_SUCCESS 0
#define ERRNO_BADF 8
#define ERRNO_NOSYS 52

#ifndef APRV_CLOCK_TRAP
__attribute__((import_module("aprv"), import_name("clock_now_ms")))
extern double aprv_clock_now_ms(void);
#endif

#ifdef APRV_HOST_RANDOM
__attribute__((import_module("aprv"), import_name("random_get")))
extern int32_t aprv_random_get(int32_t buf, int32_t len);
#endif

#define W(name) __imported_wasi_snapshot_preview1_##name

#ifndef APRV_KEEP_WASI_RANDOM_CLOCK
// (-DAPRV_KEEP_WASI_RANDOM_CLOCK: clock_time_get, clock_res_get and
// random_get stay real WASI imports, for the WASI 0.2 adapter component.)
int32_t W(clock_time_get)(int32_t id, int64_t precision, int32_t out) {
  (void)id; (void)precision;
#ifdef APRV_CLOCK_TRAP
  // Component build: the core's clock comes through the WIT import; no C
  // code may read a clock of its own (AWS-LC does not).
  (void)out;
  __builtin_trap();
#endif
#ifndef APRV_CLOCK_TRAP
  double ms = aprv_clock_now_ms();
  // Not a finite instant after 1970: answer 1970, where no Apple chain is
  // valid (fails closed).
  uint64_t ns = (ms == ms && ms > 0.0 && ms < 1.8e16) ? (uint64_t)ms * 1000000ull : 0;
  *(uint64_t *)(uintptr_t)out = ns;
  return ERRNO_SUCCESS;
#endif
}
int32_t W(clock_res_get)(int32_t id, int32_t out) {
  (void)id;
  *(uint64_t *)(uintptr_t)out = 1000000ull;
  return ERRNO_SUCCESS;
}
int32_t W(random_get)(int32_t buf, int32_t len) {
#ifdef APRV_HOST_RANDOM
  return aprv_random_get(buf, len);
#else
  (void)buf; (void)len;
  __builtin_trap();
#endif
}
#endif  // APRV_KEEP_WASI_RANDOM_CLOCK
int32_t W(environ_sizes_get)(int32_t count, int32_t size) {
  *(uint32_t *)(uintptr_t)count = 0;
  *(uint32_t *)(uintptr_t)size = 0;
  return ERRNO_SUCCESS;
}
int32_t W(environ_get)(int32_t environ, int32_t buf) { (void)environ; (void)buf; return ERRNO_SUCCESS; }
int32_t W(args_sizes_get)(int32_t count, int32_t size) {
  *(uint32_t *)(uintptr_t)count = 0;
  *(uint32_t *)(uintptr_t)size = 0;
  return ERRNO_SUCCESS;
}
int32_t W(args_get)(int32_t argv, int32_t buf) { (void)argv; (void)buf; return ERRNO_SUCCESS; }
_Noreturn void W(proc_exit)(int32_t code) { (void)code; __builtin_trap(); }
int32_t W(sched_yield)(void) { return ERRNO_SUCCESS; }

// No descriptors exist: no stdio, no preopens, no files.
int32_t W(fd_prestat_get)(int32_t fd, int32_t out) { (void)fd; (void)out; return ERRNO_BADF; }
int32_t W(fd_prestat_dir_name)(int32_t fd, int32_t p, int32_t l) { (void)fd; (void)p; (void)l; return ERRNO_BADF; }
int32_t W(fd_write)(int32_t fd, int32_t iovs, int32_t n, int32_t out) { (void)fd; (void)iovs; (void)n; (void)out; return ERRNO_BADF; }
int32_t W(fd_read)(int32_t fd, int32_t iovs, int32_t n, int32_t out) { (void)fd; (void)iovs; (void)n; (void)out; return ERRNO_BADF; }
int32_t W(fd_close)(int32_t fd) { (void)fd; return ERRNO_BADF; }
int32_t W(fd_seek)(int32_t fd, int64_t off, int32_t whence, int32_t out) { (void)fd; (void)off; (void)whence; (void)out; return ERRNO_BADF; }
int32_t W(fd_fdstat_get)(int32_t fd, int32_t out) { (void)fd; (void)out; return ERRNO_BADF; }
int32_t W(fd_fdstat_set_flags)(int32_t fd, int32_t flags) { (void)fd; (void)flags; return ERRNO_BADF; }
int32_t W(fd_filestat_get)(int32_t fd, int32_t out) { (void)fd; (void)out; return ERRNO_BADF; }
int32_t W(fd_readdir)(int32_t fd, int32_t buf, int32_t len, int64_t cookie, int32_t out) {
  (void)fd; (void)buf; (void)len; (void)cookie; (void)out; return ERRNO_BADF;
}
int32_t W(path_open)(int32_t fd, int32_t df, int32_t p, int32_t pl, int32_t of, int64_t rb, int64_t ri,
                     int32_t ff, int32_t out) {
  (void)fd; (void)df; (void)p; (void)pl; (void)of; (void)rb; (void)ri; (void)ff; (void)out; return ERRNO_NOSYS;
}
int32_t W(path_filestat_get)(int32_t fd, int32_t flags, int32_t p, int32_t pl, int32_t out) {
  (void)fd; (void)flags; (void)p; (void)pl; (void)out; return ERRNO_NOSYS;
}
