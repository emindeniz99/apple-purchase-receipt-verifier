// The link-time host of aprv.wasm (docs/rust-core/ARCHITECTURE.md §3).
//
// wasi-libc calls each WASI preview-1 function through a symbol named
// __imported_wasi_snapshot_preview1_<name>, which carries the import
// attributes (libc-bottom-half/sources/__wasilibc_real.c). This file
// DEFINES those symbols, so wasm-ld resolves them inside the module and the
// finished aprv.wasm imports no "wasi_snapshot_preview1" function at all.
// Nothing in wasi-libc, OpenSSL or the Rust code is patched.
//
// Every function traps, except two:
//
//   random_get      forwards to the Rust side (src/lib.rs), which asks the
//                   host through the module's one import, random-get, and
//                   traps on an answer of the wrong length. OpenSSL draws
//                   random bytes only for EC blinding and its DRBG.
//   clock_time_get  answers the now-ms of the verify call in progress, 0
//                   during init. The core never reads a clock: its instant
//                   is the call's argument. OpenSSL's DRBG reads this one.
//
// A call to a file, directory, environment, argument, exit or scheduling
// function stops the verification instead of taking a path nobody
// measured. The list below is every function wasi-libc references in this
// build: one missing here shows up as a wasi_snapshot_preview1 import, and
// build.sh refuses a module with any import but random-get.
//
// The Rust side hands its two values over through the two setters below, so
// no Rust symbol has to be visible to this file, and nothing but the
// interface is exported.
#include <stddef.h>
#include <stdint.h>

#define ERRNO_SUCCESS 0
#define W(name) __imported_wasi_snapshot_preview1_##name
#define TRAP() __builtin_trap()

static uint64_t now_ms;
static int32_t (*random_source)(uint8_t *buf, size_t len);

// Called by the Rust side before every verify call (0 after it).
void aprv_wasi_set_now_ms(uint64_t ms) { now_ms = ms; }

// Called by the Rust side at init, before anything can need randomness.
void aprv_wasi_set_random_source(int32_t (*source)(uint8_t *buf, size_t len)) {
  random_source = source;
}

// --- the two that answer ---------------------------------------------------

int32_t W(random_get)(int32_t buf, int32_t len) {
  if (random_source == 0 || len < 0) TRAP();
  return random_source((uint8_t *)(uintptr_t)buf, (size_t)len);
}

int32_t W(clock_time_get)(int32_t id, int64_t precision, int32_t out) {
  (void)id;
  (void)precision;
  // Nanoseconds, saturated where milliseconds no longer fit (year 586,912).
  uint64_t ns = now_ms > UINT64_MAX / 1000000u ? UINT64_MAX : now_ms * 1000000u;
  *(uint64_t *)(uintptr_t)out = ns;
  return ERRNO_SUCCESS;
}

// --- every other function wasi-libc references: a trap --------------------

int32_t W(clock_res_get)(int32_t id, int32_t out) { (void)id; (void)out; TRAP(); }
int32_t W(environ_sizes_get)(int32_t count, int32_t size) { (void)count; (void)size; TRAP(); }
int32_t W(environ_get)(int32_t environ, int32_t buf) { (void)environ; (void)buf; TRAP(); }
int32_t W(args_sizes_get)(int32_t count, int32_t size) { (void)count; (void)size; TRAP(); }
int32_t W(args_get)(int32_t argv, int32_t buf) { (void)argv; (void)buf; TRAP(); }
_Noreturn void W(proc_exit)(int32_t code) { (void)code; TRAP(); }
int32_t W(sched_yield)(void) { TRAP(); }
int32_t W(fd_prestat_get)(int32_t fd, int32_t out) { (void)fd; (void)out; TRAP(); }
int32_t W(fd_prestat_dir_name)(int32_t fd, int32_t p, int32_t l) { (void)fd; (void)p; (void)l; TRAP(); }
int32_t W(fd_write)(int32_t fd, int32_t iovs, int32_t n, int32_t out) { (void)fd; (void)iovs; (void)n; (void)out; TRAP(); }
int32_t W(fd_read)(int32_t fd, int32_t iovs, int32_t n, int32_t out) { (void)fd; (void)iovs; (void)n; (void)out; TRAP(); }
int32_t W(fd_close)(int32_t fd) { (void)fd; TRAP(); }
int32_t W(fd_seek)(int32_t fd, int64_t off, int32_t whence, int32_t out) { (void)fd; (void)off; (void)whence; (void)out; TRAP(); }
int32_t W(fd_fdstat_get)(int32_t fd, int32_t out) { (void)fd; (void)out; TRAP(); }
int32_t W(fd_fdstat_set_flags)(int32_t fd, int32_t flags) { (void)fd; (void)flags; TRAP(); }
int32_t W(fd_filestat_get)(int32_t fd, int32_t out) { (void)fd; (void)out; TRAP(); }
int32_t W(fd_readdir)(int32_t fd, int32_t buf, int32_t len, int64_t cookie, int32_t out) {
  (void)fd; (void)buf; (void)len; (void)cookie; (void)out; TRAP();
}
int32_t W(path_open)(int32_t fd, int32_t df, int32_t p, int32_t pl, int32_t of, int64_t rb, int64_t ri,
                     int32_t ff, int32_t out) {
  (void)fd; (void)df; (void)p; (void)pl; (void)of; (void)rb; (void)ri; (void)ff; (void)out; TRAP();
}
int32_t W(path_filestat_get)(int32_t fd, int32_t flags, int32_t p, int32_t pl, int32_t out) {
  (void)fd; (void)flags; (void)p; (void)pl; (void)out; TRAP();
}
