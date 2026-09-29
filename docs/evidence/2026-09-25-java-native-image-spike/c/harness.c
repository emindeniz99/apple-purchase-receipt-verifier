/*
 * C harness for the spike: smoke test, ABI misuse, threads, leak loop and
 * benchmark, against either C ABI:
 *
 *   native image: cc -O2 -DUSE_NI   -I$OUT harness.c -L$OUT -lapple_purchase_receipt_verifier_java -lpthread -o h-ni
 *   rust core:    cc -O2 -DUSE_RUST -I$REPO/rust/ffi/include harness.c -L$RUST -lapple_purchase_receipt_verifier_ffi -lpthread -o h-rust
 *
 *   ./h-ni smoke   <receipt.b64> <transaction.jws> <jws-root.der>
 *   ./h-ni bench   <receipt.b64> <transaction.jws> <jws-root.der> <op> <threads> <seconds>
 *   ./h-ni leak    <receipt.b64> <transaction.jws> <jws-root.der> <iterations>
 *   ./h-ni hazards <receipt.b64> <transaction.jws> <jws-root.der>
 *   ./h-ni startup [cycles]
 *
 * op: receipt | jws | endpoint. With SHARED=1 in the environment, every
 * worker thread calls through the main thread's three handles (each worker
 * still attaches its own IsolateThread) instead of building its own. Every output string is compared with the
 * one the first call produced (request_date aside, the endpoint clock is
 * fixed), so a corrupted or cross-talking result fails the run.
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef USE_NI
#include "libapple_purchase_receipt_verifier_java.h"
#else
#include "apple_purchase_receipt_verifier.h"
#endif

static double now_s(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}

static long rss_kb(void) {
  FILE *f = fopen("/proc/self/status", "r");
  char line[256];
  long kb = -1;
  while (f && fgets(line, sizeof line, f))
    if (!strncmp(line, "VmRSS:", 6)) kb = atol(line + 6);
  if (f) fclose(f);
  return kb;
}

static char *slurp(const char *path, size_t *len, int trim) {
  FILE *f = fopen(path, "rb");
  if (!f) { perror(path); exit(2); }
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  rewind(f);
  char *buf = malloc(n + 1);
  if (fread(buf, 1, n, f) != (size_t)n) { perror(path); exit(2); }
  buf[n] = 0;
  fclose(f);
  while (trim && n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ')) buf[--n] = 0;
  if (len) *len = n;
  return buf;
}

__attribute__((unused)) static char *b64(const unsigned char *in, size_t n) {
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

/* ---- inputs shared by every thread ---- */
static char *receipt_b64, *jws, *body;
static size_t receipt_len, jws_len, body_len;
static unsigned char *jws_root; static size_t jws_root_len;
static const char *BUNDLE = "dev.bonzer.weeka.app";

/* ---- one adapter per ABI: a context per thread, and three calls ---- */
typedef struct { void *thread; void *receipt, *jws, *endpoint; } ctx_t;

#ifdef USE_NI
static graal_isolate_t *isolate;
static graal_isolatethread_t *main_thread;

static void *mk(graal_isolatethread_t *t, void *(*f)(graal_isolatethread_t *, char *, char **), const char *opts) {
  char *err = NULL;
  void *h = f(t, (char *)opts, &err);
  if (!h) { fprintf(stderr, "constructor failed: %s\n", err ? err : "?"); exit(3); }
  return h;
}

static void runtime_up(void) {
  main_thread = aprvj_runtime_new();
  if (!main_thread) { fprintf(stderr, "aprvj_runtime_new failed\n"); exit(3); }
  isolate = aprvj_runtime_isolate(main_thread);
}

static void ctx_open(ctx_t *c, int attach) {
  c->thread = attach ? aprvj_thread_attach(isolate) : main_thread;
  graal_isolatethread_t *t = c->thread;
  char opts[4096];
  snprintf(opts, sizeof opts, "{\"bundleId\":\"%s\"}", BUNDLE);
  c->receipt = mk(t, aprvj_receipt_verifier_new, opts);
  char *root = b64(jws_root, jws_root_len);
  char *jopts = malloc(strlen(root) + 256);
  sprintf(jopts, "{\"bundleId\":\"com.example.app\",\"acceptedEnvironments\":[\"Sandbox\"],\"roots\":[\"%s\"]}", root);
  c->jws = mk(t, aprvj_jws_verifier_new, jopts);
  free(root); free(jopts);
  c->endpoint = mk(t, aprvj_endpoint_new, "{\"environment\":\"Sandbox\",\"nowMillis\":1767225600000}");
}

static void ctx_close(ctx_t *c, int detach) {
  aprvj_handle_free(c->thread, c->receipt);
  aprvj_handle_free(c->thread, c->jws);
  aprvj_handle_free(c->thread, c->endpoint);
  if (detach) aprvj_thread_detach(c->thread);
}

static int call(ctx_t *c, int op, char **out) {
  if (op == 0) return aprvj_verify_receipt(c->thread, c->receipt, receipt_b64, receipt_len, 1, NULL, 0, out);
  if (op == 1) return aprvj_verify_jws(c->thread, c->jws, jws, jws_len, 0, out);
  return aprvj_verify_receipt_json(c->thread, c->endpoint, body, body_len, out);
}
static void sfree(ctx_t *c, char *s) { aprvj_string_free(c->thread, s); }
static void runtime_down(void) { printf("runtime_free: %d\n", aprvj_runtime_free(main_thread)); }
#else
static void runtime_up(void) {}
static void runtime_down(void) {}
static void ctx_open(ctx_t *c, int attach) {
  (void)attach;
  c->receipt = aprv_verifier_new_receipt(BUNDLE);
  const uint8_t *ders[1] = {jws_root};
  size_t lens[1] = {jws_root_len};
  c->jws = aprv_verifier_new_jws_with_roots("com.example.app", APRV_ENVIRONMENT_SANDBOX, 0, ders, lens, 1);
  int64_t clock = 1767225600000LL;
  c->endpoint = aprv_endpoint_new_with_roots_and_clock(APRV_ENVIRONMENT_SANDBOX, NULL, NULL, 0, &clock);
  if (!c->receipt || !c->jws || !c->endpoint) { fprintf(stderr, "constructor failed\n"); exit(3); }
}
static void ctx_close(ctx_t *c, int detach) {
  (void)detach;
  aprv_verifier_free_receipt(c->receipt);
  aprv_verifier_free_jws(c->jws);
  aprv_endpoint_free(c->endpoint);
}
static int call(ctx_t *c, int op, char **out) {
  AprvResult r = {0};
  if (op == 0) { int s = aprv_verify_receipt_base64(c->receipt, receipt_b64, &r); *out = r.json; return s; }
  if (op == 1) { int s = aprv_verify_transaction(c->jws, jws, &r); *out = r.json; return s; }
  return aprv_verify_receipt_endpoint_json(c->endpoint, body, out);
}
static void sfree(ctx_t *c, char *s) { (void)c; aprv_string_free(s); }
#endif

static char *reference[3];

static void load(char **argv) {
  size_t n;
  receipt_b64 = slurp(argv[2], &receipt_len, 1);
  /* the fixture is MIME-wrapped base64; the ABI takes the client string, so unwrap it */
  char *w = receipt_b64;
  for (char *r = receipt_b64; *r; r++) if (*r != '\n' && *r != '\r') *w++ = *r;
  *w = 0; receipt_len = w - receipt_b64;
  jws = slurp(argv[3], &jws_len, 1);
  jws_root = (unsigned char *)slurp(argv[4], &n, 0); /* DER: binary, never trimmed */
  jws_root_len = n;
  body = malloc(receipt_len + 32);
  body_len = sprintf(body, "{\"receipt-data\":\"%s\"}", receipt_b64);
}

/* ---- threads ---- */
typedef struct { int op; double seconds; long calls; long bad; int attach; } job_t;

static ctx_t *shared; /* SHARED=1: every worker calls through the main thread's handles */

static void *worker(void *arg) {
  job_t *j = arg;
  ctx_t c;
  if (shared) {
    c = *shared;
#ifdef USE_NI
    c.thread = aprvj_thread_attach(isolate);
#endif
  } else {
    ctx_open(&c, j->attach);
  }
  double end = now_s() + j->seconds;
  while (now_s() < end) {
    for (int k = 0; k < 20; k++) {
      char *out = NULL;
      int code = call(&c, j->op, &out);
      if (code != 0 || !out || strcmp(out, reference[j->op])) j->bad++;
      sfree(&c, out);
      j->calls++;
    }
  }
  if (shared) {
#ifdef USE_NI
    aprvj_thread_detach(c.thread);
#endif
  } else {
    ctx_close(&c, j->attach);
  }
  return NULL;
}

static const char *OPS[] = {"receipt", "jws", "endpoint"};

static int op_of(const char *s) {
  for (int i = 0; i < 3; i++) if (!strcmp(s, OPS[i])) return i;
  fprintf(stderr, "unknown op %s\n", s); exit(2);
}

static void make_references(ctx_t *c) {
  for (int op = 0; op < 3; op++) {
    char *out = NULL;
    int code = call(c, op, &out);
    if (code != 0 || !out) { fprintf(stderr, "%s reference call failed: %d %s\n", OPS[op], code, out ? out : ""); exit(4); }
    reference[op] = strdup(out);
    sfree(c, out);
  }
}

static int bench(char **argv) {
  int op = op_of(argv[5]), threads = atoi(argv[6]);
  double seconds = atof(argv[7]);
  double t0 = now_s();
  runtime_up();
  double t1 = now_s();
  long rss_start = rss_kb();
  ctx_t c;
  ctx_open(&c, 0);
  double t2 = now_s();
  char *out = NULL;
  int code = call(&c, op, &out);
  double t3 = now_s();
  if (code) { fprintf(stderr, "first call failed %d %s\n", code, out); return 4; }
  sfree(&c, out);
  make_references(&c);
  /* single-thread latency after a warm-up */
  double warm_end = now_s() + 3.0;
  long warm = 0;
  while (now_s() < warm_end) { call(&c, op, &out); sfree(&c, out); warm++; }
  enum { N = 2000 };
  static double lat[N];
  for (int i = 0; i < N; i++) {
    double a = now_s(); call(&c, op, &out); lat[i] = now_s() - a; sfree(&c, out);
  }
  int cmp(const void *x, const void *y) { double d = *(double *)x - *(double *)y; return d < 0 ? -1 : d > 0; }
  qsort(lat, N, sizeof lat[0], cmp);
  double sum = 0; for (int i = 0; i < N; i++) sum += lat[i];
  long rss_warm = rss_kb();
  /* throughput: `threads` workers (the main thread's context stays idle) */
  if (getenv("SHARED")) shared = &c;
  pthread_t tid[64];
  job_t jobs[64];
  for (int i = 0; i < threads; i++) { jobs[i] = (job_t){op, seconds, 0, 0, 1}; pthread_create(&tid[i], NULL, worker, &jobs[i]); }
  long calls = 0, bad = 0;
  for (int i = 0; i < threads; i++) { pthread_join(tid[i], NULL); calls += jobs[i].calls; bad += jobs[i].bad; }
  long rss_load = rss_kb();
  printf("{\"op\":\"%s\",\"threads\":%d,\"shared_handles\":%d,\"runtime_new_ms\":%.2f,\"ctx_open_ms\":%.2f,\"first_call_ms\":%.2f,"
         "\"warmup_calls\":%ld,\"mean_us\":%.1f,\"p50_us\":%.1f,\"p99_us\":%.1f,\"throughput_per_s\":%.0f,"
         "\"calls\":%ld,\"mismatched\":%ld,\"rss_kb_after_runtime_new\":%ld,\"rss_kb_after_warmup\":%ld,\"rss_kb_after_load\":%ld}\n",
         OPS[op], threads, shared != NULL, (t1 - t0) * 1e3, (t2 - t1) * 1e3, (t3 - t2) * 1e3, warm, sum / N * 1e6,
         lat[N / 2] * 1e6, lat[N * 99 / 100] * 1e6, calls / seconds, calls, bad, rss_start, rss_warm, rss_load);
  ctx_close(&c, 0);
  runtime_down();
  return bad ? 5 : 0;
}

static int leak(char **argv) {
  long iterations = atol(argv[5]);
  runtime_up();
  ctx_t c;
  ctx_open(&c, 0);
  make_references(&c);
  printf("iteration,rss_kb\n");
  for (long i = 0; i <= iterations; i++) {
    for (int op = 0; op < 3; op++) {
      char *out = NULL;
      int code = call(&c, op, &out);
      if (code || strcmp(out, reference[op])) { fprintf(stderr, "mismatch at %ld\n", i); return 5; }
      sfree(&c, out);
    }
    /* handles too: build and free a fresh set every 100 iterations */
    if (i % 100 == 0) { ctx_close(&c, 0); ctx_open(&c, 0); }
    if (i % (iterations / 20 ? iterations / 20 : 1) == 0) printf("%ld,%ld\n", i, rss_kb());
  }
  ctx_close(&c, 0);
  runtime_down();
  return 0;
}

#ifdef USE_NI
static int failures;
#define CHECK(cond, ...) do { if (cond) printf("ok   "); else { printf("FAIL "); failures++; } printf(__VA_ARGS__); printf("\n"); } while (0)

static void *free_elsewhere(void *s) {
  graal_isolatethread_t *t = aprvj_thread_attach(isolate);
  aprvj_string_free(t, s);
  aprvj_thread_detach(t);
  return NULL;
}

static int smoke(void) {
  ctx_t c;
  runtime_up();
  ctx_open(&c, 0);
  graal_isolatethread_t *t = c.thread;
  char *out = NULL;
  int code = aprvj_self_check(t, &out);
  CHECK(code == 0, "self_check %d %s", code, out);
  aprvj_string_free(t, out);

  code = call(&c, 0, &out);
  CHECK(code == 0 && strstr(out, "\"bundleId\":\"dev.bonzer.weeka.app\""), "g5 receipt verifies: %.80s", out);
  aprvj_string_free(t, out);
  code = call(&c, 1, &out);
  CHECK(code == 0 && strstr(out, "\"productId\":\"com.example.app.pro\""), "generated JWS verifies: %.80s", out);
  aprvj_string_free(t, out);
  code = call(&c, 2, &out);
  CHECK(code == 0 && !strncmp(out, "{\"status\":0,", 12), "endpoint (Sandbox) answers status 0: %.60s", out);
  aprvj_string_free(t, out);

  char *err = NULL;
  void *prod = aprvj_endpoint_new(t, "{\"environment\":\"Production\"}", &err);
  code = aprvj_verify_receipt_json(t, prod, body, body_len, &out);
  CHECK(code == 0 && !strcmp(out, "{\"status\":21007}"), "endpoint (Production) answers %s", out);
  aprvj_string_free(t, out);
  aprvj_handle_free(t, prod);

  void *wrong = aprvj_receipt_verifier_new(t, "{\"bundleId\":\"com.other\"}", &err);
  code = aprvj_verify_receipt(t, wrong, receipt_b64, receipt_len, 1, NULL, 0, &out);
  CHECK(code == 6, "wrong bundle id -> 6 WRONG_BUNDLE_ID: %.90s", out);
  aprvj_string_free(t, out);
  aprvj_handle_free(t, wrong);

  /* ABI misuse: every one returns a code, none crashes */
  code = aprvj_verify_receipt(t, NULL, receipt_b64, receipt_len, 1, NULL, 0, &out);
  CHECK(code == -1, "NULL handle -> -1: %s", out); aprvj_string_free(t, out);
  code = aprvj_verify_receipt(t, c.receipt, NULL, 5, 0, NULL, 0, &out);
  CHECK(code == -1, "NULL bytes, length 5 -> -1: %s", out); aprvj_string_free(t, out);
  code = aprvj_verify_receipt(t, c.receipt, NULL, 0, 0, NULL, 0, &out);
  CHECK(code == 9, "NULL bytes, length 0 -> 9 INVALID_RECEIPT_FORMAT: %.90s", out); aprvj_string_free(t, out);
  code = aprvj_verify_receipt(t, c.receipt, "", 0, 1, NULL, 0, &out);
  CHECK(code == 9, "empty base64 -> 9: %.90s", out); aprvj_string_free(t, out);
  code = aprvj_verify_receipt(t, c.receipt, receipt_b64, receipt_len, 1, NULL, 7, &out);
  CHECK(code == 0, "NULL guid with length 7 is 'no guid' -> 0"); aprvj_string_free(t, out);
  code = aprvj_verify_receipt(t, c.receipt, receipt_b64, receipt_len, 1, "\x01\x02", 2, &out);
  CHECK(code == 10, "wrong device guid -> 10 DEVICE_HASH_MISMATCH: %.90s", out); aprvj_string_free(t, out);
  code = aprvj_verify_jws(t, c.jws, NULL, 0, 0, &out);
  CHECK(code == 1, "NULL jws -> 1 INVALID_JWS_FORMAT: %.90s", out); aprvj_string_free(t, out);
  code = aprvj_verify_jws(t, c.jws, jws, jws_len, 99, &out);
  CHECK(code == -1, "unknown JWS operation -> -1: %.90s", out); aprvj_string_free(t, out);
  code = aprvj_verify_jws(t, c.receipt, jws, jws_len, 0, &out);
  CHECK(code == -1, "receipt handle passed as JWS handle -> -1: %.100s", out); aprvj_string_free(t, out);
  code = aprvj_verify_receipt_json(t, c.endpoint, NULL, 0, &out);
  CHECK(code == 11 && !strcmp(out, "{\"status\":21002}"), "NULL request -> 11 MALFORMED_REQUEST, %s", out); aprvj_string_free(t, out);
  code = aprvj_verify_receipt(t, c.receipt, receipt_b64, receipt_len, 1, NULL, 0, NULL);
  CHECK(code == 0, "NULL out pointer: code still returned, nothing allocated");
  void *h = aprvj_receipt_verifier_new(t, NULL, &err);
  CHECK(h == NULL && err != NULL, "NULL options -> NULL handle, error %s", err); aprvj_string_free(t, err);
  h = aprvj_jws_verifier_new(t, "{not json", &err);
  CHECK(h == NULL, "malformed options -> NULL handle, error %.100s", err); aprvj_string_free(t, err);
  h = aprvj_endpoint_new(t, "{\"environment\":\"Xcode\"}", NULL);
  CHECK(h == NULL, "Xcode endpoint refused, NULL error pointer tolerated");
  aprvj_string_free(t, NULL);
  aprvj_handle_free(t, NULL);
  CHECK(1, "string_free(NULL) and handle_free(NULL) returned");

  /* a string allocated on one OS thread, freed by another OS thread through
     its own attachment (attaching again on the SAME OS thread returns the
     same IsolateThread; see the hazards mode) */
  code = call(&c, 0, &out);
  pthread_t freer;
  pthread_create(&freer, NULL, free_elsewhere, out);
  pthread_join(freer, NULL);
  CHECK(1, "string freed by a different OS thread, attached for the purpose");

  ctx_close(&c, 0);
  runtime_down();
  /* a second runtime in the same process */
  runtime_up();
  ctx_open(&c, 0);
  code = call(&c, 0, &out);
  CHECK(code == 0, "second runtime after teardown verifies the receipt");
  aprvj_string_free(c.thread, out);
  ctx_close(&c, 0);
  runtime_down();
  printf("%d failure(s)\n", failures);
  return failures ? 1 : 0;
}

/* ---- hazards: ABI misuse that a C caller can commit. Each runs in its own
   child process; the parent reports how the child ended. ---- */
#include <signal.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

static void *call_with_foreign_thread(void *arg) {
  ctx_t *c = arg; /* c->thread belongs to the main OS thread */
  char *out = NULL;
  int code = call(c, 0, &out);
  printf("    returned %d\n", code);
  return NULL;
}

static void hazard(int which) {
  ctx_t c;
  char *out = NULL;
  runtime_up();
  ctx_open(&c, 0);
  switch (which) {
  case 0: { /* re-attach the already attached OS thread, detach that, keep using the first */
    graal_isolatethread_t *again = aprvj_thread_attach(isolate);
    printf("    attach again returned the %s IsolateThread\n", again == c.thread ? "same" : "a different");
    aprvj_thread_detach(again);
    printf("    returned %d\n", call(&c, 0, &out));
    break; }
  case 1: /* free a handle twice */
    aprvj_handle_free(c.thread, c.receipt);
    aprvj_handle_free(c.thread, c.receipt);
    printf("    second handle_free returned\n");
    break;
  case 2: /* use a handle after freeing it */
    aprvj_handle_free(c.thread, c.receipt);
    printf("    returned %d %s\n", call(&c, 0, &out), out ? out : "");
    break;
  case 3: /* a made-up handle value */
    c.receipt = (void *)(intptr_t)0x12345;
    printf("    returned %d %s\n", call(&c, 0, &out), out ? out : "");
    break;
  case 4: /* free a result string twice */
    call(&c, 0, &out);
    aprvj_string_free(c.thread, out);
    aprvj_string_free(c.thread, out);
    printf("    second string_free returned\n");
    break;
  case 5: /* string_free on memory the library did not allocate */
    { char local[8] = "x"; aprvj_string_free(c.thread, local); }
    printf("    string_free(stack pointer) returned\n");
    break;
  case 6: /* call after runtime_free with the stale thread pointer */
    aprvj_runtime_free(c.thread);
    printf("    returned %d\n", call(&c, 0, &out));
    break;
  case 7: /* pass another OS thread's IsolateThread from an unattached thread */
    { pthread_t t; pthread_create(&t, NULL, call_with_foreign_thread, &c); pthread_join(t, NULL); }
    break;
  case 8: /* a NULL IsolateThread */
    c.thread = NULL;
    printf("    returned %d\n", call(&c, 0, &out));
    break;
  case 9: /* a length longer than the buffer: reads past it (caller bug, not detectable) */
    { char *tiny = malloc(4); memcpy(tiny, "MII", 4);
      printf("    returned %d\n", aprvj_verify_receipt(c.thread, c.receipt, tiny, 64, 1, NULL, 0, &out)); }
    break;
  }
  fflush(stdout);
  _exit(0);
}

static const char *HAZARDS[] = {
  "attach twice on one OS thread, detach once, keep calling",
  "handle_free twice on one handle",
  "call with a handle after handle_free",
  "call with a made-up handle value",
  "string_free twice on one result",
  "string_free on a stack pointer",
  "call after runtime_free with the stale thread",
  "call from an unattached OS thread with another thread's IsolateThread",
  "call with a NULL IsolateThread",
  "input length larger than the buffer",
};

static int hazards(void) {
  for (int i = 0; i < (int)(sizeof HAZARDS / sizeof *HAZARDS); i++) {
    printf("hazard %d: %s\n", i, HAZARDS[i]);
    pid_t pid = fork();
    if (pid == 0) {
      if (!getenv("HAZARD_STDERR")) { int devnull = open("/dev/null", O_WRONLY); dup2(devnull, 2); } /* the VM's fatal-error dump goes to stderr */
      hazard(i);
    }
    int st;
    waitpid(pid, &st, 0);
    if (WIFEXITED(st)) printf("    child exited %d\n", WEXITSTATUS(st));
    else printf("    child killed by signal %d (%s)\n", WTERMSIG(st), strsignal(WTERMSIG(st)));
  }
  return 0;
}

static int startup(int cycles) {
  /* isolate creation cost, repeated in one process; prints the first five
     cycles and then every 100th, so a leak across teardowns shows in rss */
  for (int i = 0; i < cycles; i++) {
    double a = now_s();
    graal_isolatethread_t *t = aprvj_runtime_new();
    double b = now_s();
    char *out = NULL;
    aprvj_self_check(t, &out);
    double c2 = now_s();
    aprvj_string_free(t, out);
    int rc = aprvj_runtime_free(t);
    double d = now_s();
    if (i < 5 || (i + 1) % 100 == 0) printf("cycle %d: runtime_new %.2f ms, first call (self_check: provider init + 3 roots) %.2f ms, runtime_free %.2f ms (rc %d), rss %ld kB\n",
           i + 1, (b - a) * 1e3, (c2 - b) * 1e3, (d - c2) * 1e3, rc, rss_kb());
  }
  return 0;
}
#endif

int main(int argc, char **argv) {
  if (argc < 2) { fprintf(stderr, "usage: see the header comment\n"); return 2; }
  setvbuf(stdout, NULL, _IOLBF, 0); /* a fatal abort must not eat the lines before it */
#ifdef USE_NI
  if (!strcmp(argv[1], "startup")) return startup(argc > 2 ? atoi(argv[2]) : 5);
#endif
  if (argc < 5) { fprintf(stderr, "usage: see the header comment\n"); return 2; }
  load(argv);
#ifdef USE_NI
  if (!strcmp(argv[1], "smoke")) return smoke();
  if (!strcmp(argv[1], "hazards")) return hazards();
#endif
  if (!strcmp(argv[1], "bench") && argc == 8) return bench(argv);
  if (!strcmp(argv[1], "leak") && argc == 6) return leak(argv);
  fprintf(stderr, "unknown mode\n");
  return 2;
}
