/*
 * One verification through the C ABI, with nothing else in the process:
 * no interpreter, no TLS stack, no config of its own. Used where the
 * question is what the linked library does on its own (strace for files and
 * sockets), and as the target of the sanitizer and fuzz runs.
 *
 *   cc -O1 -g -I$REPO/rust/ffi/include c/run1.c -L<release dir> \
 *      -lapple_purchase_receipt_verifier_ffi -Wl,-rpath,<release dir> -o run1
 *
 *   run1 receipt <input.der> <bundle-id> <root.der>...
 *   run1 jws     <input.jws> <bundle-id> <root.der>...
 *   run1 loop    <n> receipt|jws <input> <bundle-id> <root.der>...   (same, n times)
 *
 * Prints "<code> <json>" for the last call. Exit status 0 unless an
 * argument is unusable. In loop mode it also prints to stderr the current
 * resident set (VmRSS from /proc/self/status) after the first call and
 * after the last one, so a per-call leak shows as growth.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "apple_purchase_receipt_verifier.h"

static long vm_rss_kb(void) {
  FILE *f = fopen("/proc/self/status", "r");
  char line[256];
  long kb = -1;
  while (f && fgets(line, sizeof line, f))
    if (!strncmp(line, "VmRSS:", 6)) kb = atol(line + 6);
  if (f) fclose(f);
  return kb;
}

static uint8_t *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); exit(2); }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  rewind(f);
  uint8_t *buf = malloc(n + 1);
  if (fread(buf, 1, n, f) != (size_t)n) { perror(path); exit(2); }
  buf[n] = 0;
  fclose(f);
  *len = n;
  return buf;
}

int main(int argc, char **argv) {
  long loops = 1;
  if (argc > 2 && !strcmp(argv[1], "loop")) { loops = atol(argv[2]); argv += 2; argc -= 2; }
  if (argc < 5) { fprintf(stderr, "usage: run1 [loop n] receipt|jws <input> <bundle> <root.der>...\n"); return 2; }
  int is_jws = !strcmp(argv[1], "jws");
  size_t len;
  uint8_t *input = slurp(argv[2], &len);
  size_t count = argc - 4;
  const uint8_t **ders = calloc(count, sizeof *ders);
  size_t *lens = calloc(count, sizeof *lens);
  for (size_t i = 0; i < count; i++) ders[i] = slurp(argv[4 + i], &lens[i]);
  int32_t code = -99;
  AprvResult r = {0};
  if (is_jws) {
    while (len && (input[len - 1] == '\n' || input[len - 1] == '\r')) input[--len] = 0;
    AprvJwsVerifier *v = aprv_verifier_new_jws_with_roots(argv[3], APRV_ENVIRONMENT_SANDBOX, 0, ders, lens, count);
    if (!v) { fprintf(stderr, "constructor refused\n"); return 3; }
    for (long i = 0; i < loops; i++) {
      if (i) aprv_string_free(r.json);
      code = aprv_verify_transaction(v, (const char *)input, &r);
      if (loops > 1 && i == 0) fprintf(stderr, "rss_after_first_kb %ld\n", vm_rss_kb());
    }
    aprv_verifier_free_jws(v);
  } else {
    AprvReceiptVerifier *v = aprv_verifier_new_receipt_with_roots(argv[3], ders, lens, count);
    if (!v) { fprintf(stderr, "constructor refused\n"); return 3; }
    for (long i = 0; i < loops; i++) {
      if (i) aprv_string_free(r.json);
      code = aprv_verify_receipt_der(v, input, len, &r);
      if (loops > 1 && i == 0) fprintf(stderr, "rss_after_first_kb %ld\n", vm_rss_kb());
    }
    aprv_verifier_free_receipt(v);
  }
  if (loops > 1) fprintf(stderr, "rss_after_last_kb %ld calls %ld\n", vm_rss_kb(), loops);
  printf("%d %.160s\n", code, r.json ? r.json : "");
  aprv_string_free(r.json);
  for (size_t i = 0; i < count; i++) free((void *)ders[i]);
  free(ders);
  free(lens);
  free(input);
  return 0;
}
