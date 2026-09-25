/*
 * Attempted PGO training run for a --pgo-instrument build of the SHARED
 * library. It creates the isolate through graal_create_isolate with one
 * runtime option, runs each operation <calls> times, and tears the isolate
 * down. It did not produce a profile: the instrumented shared library knows
 * no -XX:ProfilesDumpFile ("Could not find option"), -XX:PrintFlags= lists
 * no profile option, and teardown writes no .iprof. The PGO build in the
 * evidence note trained an executable instead (bench/JvmBench.java).
 *
 *   cc -O2 -I$OUT pgo_train.c -L$INSTRUMENTED -l:libaprvj_pgo_instrumented.so -o pgo_train
 *   ./pgo_train <receipt.b64> <transaction.jws> <jws-root.der> <runtime option> <calls>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "libapple_purchase_receipt_verifier_java.h"

static char *slurp(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); exit(2); }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  rewind(f);
  char *buf = malloc(n + 1);
  if (fread(buf, 1, n, f) != (size_t)n) exit(2);
  buf[n] = 0;
  fclose(f);
  *len = n;
  return buf;
}

static char *b64(const unsigned char *in, size_t n) {
  static const char *a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  char *out = malloc(4 * ((n + 2) / 3) + 1), *p = out;
  for (size_t i = 0; i < n; i += 3) {
    unsigned v = in[i] << 16 | (i + 1 < n ? in[i + 1] << 8 : 0) | (i + 2 < n ? in[i + 2] : 0);
    *p++ = a[v >> 18 & 63]; *p++ = a[v >> 12 & 63];
    *p++ = i + 1 < n ? a[v >> 6 & 63] : '=';
    *p++ = i + 2 < n ? a[v & 63] : '=';
  }
  *p = 0;
  return out;
}

int main(int argc, char **argv) {
  if (argc != 6) { fprintf(stderr, "usage: see the header comment\n"); return 2; }
  size_t rlen, jlen, dlen;
  char *receipt = slurp(argv[1], &rlen), *w = receipt;
  for (char *r = receipt; *r; r++) if (*r != '\n' && *r != '\r') *w++ = *r;
  *w = 0; rlen = w - receipt;
  char *jws = slurp(argv[2], &jlen);
  while (jlen && (jws[jlen - 1] == '\n' || jws[jlen - 1] == '\r')) jws[--jlen] = 0;
  unsigned char *root = (unsigned char *)slurp(argv[3], &dlen);
  char dump[4096];
  snprintf(dump, sizeof dump, "%s", argv[4]); /* a runtime option, e.g. -XX:PrintFlags= */
  long calls = atol(argv[5]);

  char *args[] = {"pgo_train", dump};
  graal_create_isolate_params_t params;
  memset(&params, 0, sizeof params);
  params.version = __graal_create_isolate_params_version;
  params.argc = 2;
  params.argv = args;
  graal_isolate_t *isolate;
  graal_isolatethread_t *t;
  if (graal_create_isolate(&params, &isolate, &t)) { fprintf(stderr, "graal_create_isolate failed\n"); return 3; }

  char *err = NULL, *out = NULL;
  void *rv = aprvj_receipt_verifier_new(t, "{\"bundleId\":\"dev.bonzer.weeka.app\"}", &err);
  char *rb = b64(root, dlen), *jopts = malloc(strlen(rb) + 256);
  sprintf(jopts, "{\"bundleId\":\"com.example.app\",\"acceptedEnvironments\":[\"Sandbox\"],\"roots\":[\"%s\"]}", rb);
  void *jv = aprvj_jws_verifier_new(t, jopts, &err);
  void *ep = aprvj_endpoint_new(t, "{\"environment\":\"Sandbox\",\"nowMillis\":1767225600000}", &err);
  char *body = malloc(rlen + 32);
  size_t blen = sprintf(body, "{\"receipt-data\":\"%s\"}", receipt);
  long bad = 0;
  for (long i = 0; i < calls; i++) {
    bad += aprvj_verify_receipt(t, rv, receipt, rlen, 1, NULL, 0, &out) != 0; aprvj_string_free(t, out);
    bad += aprvj_verify_jws(t, jv, jws, jlen, 0, &out) != 0; aprvj_string_free(t, out);
    bad += aprvj_verify_receipt_json(t, ep, body, blen, &out) != 0; aprvj_string_free(t, out);
  }
  aprvj_handle_free(t, rv); aprvj_handle_free(t, jv); aprvj_handle_free(t, ep);
  printf("%ld calls per operation, %ld failed; graal_tear_down_isolate: %d\n", calls, bad, graal_tear_down_isolate(t));
  return bad ? 1 : 0;
}
