/*
 * Spike only (2026-09-27, round 9): a native host for aprv.wasm (ABI v1)
 * over WAMR 2.4.5's embedding API (wasm_export.h), linked to one libiwasm
 * build per execution mode. The same interface as ../wasmi-host:
 *
 *   aprv-wamr serve MODULE [--running-mode M]          line protocol on stdin/stdout (py/driver.py)
 *   aprv-wamr first MODULE G5 [--running-mode M]       one cold process to its first verified g5 (JSON)
 *   aprv-wamr bench MODULE G5 JWS [--running-mode M]   warm-up curve and steady state (JSON lines)
 *
 * --running-mode: default | interp | fast-jit | llvm-jit | multi-tier
 * (RuntimeInitArgs.running_mode; the library decides what it supports).
 *
 * The host registers exactly the module's two imports, aprv.clock_now_ms
 * "()F" and aprv.random_get "(ii)i", and runs the ABI v1 call lifecycle.
 * No WASI, no libc-builtin: the module needs neither.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include "wasm_export.h"

#define STACK_SIZE (1024 * 1024) /* exec env (Wasm operand) stack */
#define MAX_INST 64

static uint64_t clock_calls, random_calls;
static wasm_module_t module;
static const char *mode_arg = "default";

static double now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}

static long long mono_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

static double clock_now_ms(wasm_exec_env_t env)
{
    (void)env;
    clock_calls++;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (double)((uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000);
}

static int32_t random_get(wasm_exec_env_t env, int32_t ptr, int32_t len)
{
    wasm_module_inst_t inst = wasm_runtime_get_module_inst(env);
    random_calls++;
    if (ptr < 0 || len < 0
        || !wasm_runtime_validate_app_addr(inst, (uint64_t)(uint32_t)ptr, (uint64_t)(uint32_t)len)) {
        wasm_runtime_set_exception(inst, "aprv.random_get out of bounds");
        return 0;
    }
    uint8_t *p = wasm_runtime_addr_app_to_native(inst, (uint64_t)(uint32_t)ptr);
    size_t done = 0;
    while (done < (size_t)len) {
        ssize_t n = getrandom(p + done, (size_t)len - done, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            wasm_runtime_set_exception(inst, "getrandom failed");
            return 0;
        }
        done += (size_t)n;
    }
    return 0;
}

static NativeSymbol natives[] = {
    { "clock_now_ms", (void *)clock_now_ms, "()F", NULL },
    { "random_get", (void *)random_get, "(ii)i", NULL },
};

typedef struct {
    wasm_module_inst_t inst;
    wasm_exec_env_t env;
    wasm_function_inst_t alloc, dealloc, call, rptr, rlen, rfree;
} Inst;

enum { OK = 0, TRAP = 1, ERR = 2 };

static char msg[1024];

/* Calls f with i32 arguments; results into res. Returns OK or TRAP (msg set). */
static int call_i32(Inst *in, wasm_function_inst_t f, uint32_t nargs, const int32_t *args, uint32_t nres, int32_t *res)
{
    wasm_val_t a[8], r[4];
    for (uint32_t i = 0; i < nargs; i++) {
        a[i].kind = WASM_I32;
        a[i].of.i32 = args[i];
    }
    if (!wasm_runtime_call_wasm_a(in->env, f, nres, r, nargs, a)) {
        const char *e = wasm_runtime_get_exception(in->inst);
        snprintf(msg, sizeof msg, "%s", e ? e : "unknown failure");
        wasm_runtime_clear_exception(in->inst);
        return TRAP;
    }
    for (uint32_t i = 0; i < nres; i++)
        res[i] = r[i].of.i32;
    return OK;
}

static uint64_t mem_len(Inst *in, uint8_t **base)
{
    wasm_memory_inst_t m = wasm_runtime_get_default_memory(in->inst);
    if (base)
        *base = wasm_memory_get_base_address(m);
    return wasm_memory_get_cur_page_count(m) * wasm_memory_get_bytes_per_page(m);
}

static void inst_free(Inst *in)
{
    if (in->env)
        wasm_runtime_destroy_exec_env(in->env);
    if (in->inst)
        wasm_runtime_deinstantiate(in->inst);
    memset(in, 0, sizeof *in);
}

static int inst_new(Inst *in)
{
    char err[256];
    memset(in, 0, sizeof *in);
    in->inst = wasm_runtime_instantiate(module, STACK_SIZE, 0, err, sizeof err);
    if (!in->inst) {
        snprintf(msg, sizeof msg, "instantiate: %s", err);
        return ERR;
    }
    in->env = wasm_runtime_create_exec_env(in->inst, STACK_SIZE);
    if (!in->env) {
        snprintf(msg, sizeof msg, "create_exec_env failed");
        inst_free(in);
        return ERR;
    }
    wasm_function_inst_t init = wasm_runtime_lookup_function(in->inst, "_initialize");
    wasm_function_inst_t version = wasm_runtime_lookup_function(in->inst, "aprv_abi_version");
    in->alloc = wasm_runtime_lookup_function(in->inst, "aprv_alloc");
    in->dealloc = wasm_runtime_lookup_function(in->inst, "aprv_dealloc");
    in->call = wasm_runtime_lookup_function(in->inst, "aprv_call");
    in->rptr = wasm_runtime_lookup_function(in->inst, "aprv_result_ptr");
    in->rlen = wasm_runtime_lookup_function(in->inst, "aprv_result_len");
    in->rfree = wasm_runtime_lookup_function(in->inst, "aprv_result_free");
    if (!init || !version || !in->alloc || !in->dealloc || !in->call || !in->rptr || !in->rlen || !in->rfree) {
        snprintf(msg, sizeof msg, "missing export");
        inst_free(in);
        return ERR;
    }
    int32_t v = 0;
    if (call_i32(in, init, 0, NULL, 0, NULL) != OK || call_i32(in, version, 0, NULL, 1, &v) != OK) {
        inst_free(in);
        return ERR;
    }
    if (v != 1) {
        snprintf(msg, sizeof msg, "APRV Wasm ABI mismatch: module=%d, caller=1", v);
        inst_free(in);
        return ERR;
    }
    return OK;
}

/* The full ABI v1 call lifecycle; *out is a malloc'd host-owned copy. */
static int invoke(Inst *in, int32_t abi, int32_t op, const uint8_t *data, uint32_t n, uint8_t **out, uint32_t *outn)
{
    int32_t p, h, rp, rn, a[4];
    int s;
    uint8_t *base;
    a[0] = (int32_t)n;
    if ((s = call_i32(in, in->alloc, 1, a, 1, &p)) != OK)
        return s;
    if (p == 0) {
        snprintf(msg, sizeof msg, "aprv_alloc(%u) failed", n);
        return ERR;
    }
    if (n) {
        uint64_t len = mem_len(in, &base);
        if ((uint64_t)(uint32_t)p + n > len) {
            snprintf(msg, sizeof msg, "input out of bounds");
            return TRAP;
        }
        memcpy(base + (uint32_t)p, data, n);
    }
    a[0] = abi, a[1] = op, a[2] = p, a[3] = (int32_t)n;
    if ((s = call_i32(in, in->call, 4, a, 1, &h)) != OK)
        return s;
    if ((s = call_i32(in, in->rptr, 1, &h, 1, &rp)) != OK || (s = call_i32(in, in->rlen, 1, &h, 1, &rn)) != OK)
        return s;
    uint64_t len = mem_len(in, &base);
    if ((uint64_t)(uint32_t)rp + (uint32_t)rn > len) {
        snprintf(msg, sizeof msg, "result out of bounds");
        return TRAP;
    }
    *outn = (uint32_t)rn;
    *out = malloc(*outn ? *outn : 1);
    memcpy(*out, base + (uint32_t)rp, *outn);
    if ((s = call_i32(in, in->rfree, 1, &h, 0, NULL)) != OK) {
        free(*out);
        return s;
    }
    a[0] = p, a[1] = (int32_t)n;
    if ((s = call_i32(in, in->dealloc, 2, a, 0, NULL)) != OK) {
        free(*out);
        return s;
    }
    return OK;
}

static long proc_status(const char *key)
{
    FILE *f = fopen("/proc/self/status", "r");
    char line[256];
    long v = 0;
    size_t k = strlen(key);
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, key, k)) {
            v = strtol(line + k, NULL, 10);
            break;
        }
    if (f)
        fclose(f);
    return v;
}

static int verified(const uint8_t *out, uint32_t n)
{
    return memmem(out, n, "\"verified\":true", 15) != NULL;
}

static uint8_t *read_file(const char *path, uint32_t *n)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "aprv-wamr: cannot open %s\n", path);
        exit(2);
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(len ? len : 1);
    if (fread(b, 1, len, f) != (size_t)len)
        exit(2);
    fclose(f);
    *n = (uint32_t)len;
    return b;
}

static const char *running_mode_name(RunningMode m)
{
    switch (m) {
        case Mode_Interp: return "interp";
        case Mode_Fast_JIT: return "fast-jit";
        case Mode_LLVM_JIT: return "llvm-jit";
        case Mode_Multi_Tier_JIT: return "multi-tier";
        default: return "default";
    }
}

static void die(const char *what)
{
    fprintf(stderr, "aprv-wamr: %s: %s\n", what, msg);
    exit(2);
}

static void bench_op(Inst *in, const char *name, int32_t op, const uint8_t *input, uint32_t n)
{
    char marks[256] = "";
    int bad = 0;
    for (int i = 1; i <= 100; i++) {
        uint8_t *out;
        uint32_t on;
        double t = now_ms();
        if (invoke(in, 1, op, input, n, &out, &on) != OK)
            die(name);
        long us = (long)((now_ms() - t) * 1000);
        bad += !verified(out, on);
        free(out);
        if (i == 1 || i == 2 || i == 5 || i == 10 || i == 100)
            snprintf(marks + strlen(marks), sizeof marks - strlen(marks), "%s\"%d\":%ld", marks[0] ? "," : "", i, us);
    }
    double t = now_ms();
    long calls = 0;
    while (calls < 20 || now_ms() - t < 2000) {
        uint8_t *out;
        uint32_t on;
        if (invoke(in, 1, op, input, n, &out, &on) != OK)
            die(name);
        bad += !verified(out, on);
        free(out);
        calls++;
    }
    double secs = (now_ms() - t) / 1e3;
    printf("{\"op\":\"%s\",\"calls_us\":{%s},\"steady_calls\":%ld,\"steady_s\":%.3f,\"per_s\":%.1f,\"mean_us\":%.0f,\"not_verified\":%d}\n",
           name, marks, calls, secs, calls / secs, secs * 1e6 / calls, bad);
    fflush(stdout);
}

/* ---- the line protocol (py/driver.py) ---- */

static int rd(void *b, size_t n) { return fread(b, 1, n, stdin) == n; }

static void reply(int status, const void *p, uint32_t n)
{
    uint8_t s = (uint8_t)status;
    fwrite(&s, 1, 1, stdout);
    fwrite(&n, 4, 1, stdout);
    if (n)
        fwrite(p, 1, n, stdout);
    fflush(stdout);
}

static void serve(void)
{
    static Inst insts[MAX_INST + 1];
    uint8_t cmd;
    while (rd(&cmd, 1)) {
        uint32_t id = 0;
        if (cmd == 'n') {
            for (id = 1; id <= MAX_INST && insts[id].inst; id++)
                ;
            if (id > MAX_INST) {
                reply(ERR, "too many instances", 18);
                continue;
            }
            if (inst_new(&insts[id]) != OK)
                reply(ERR, msg, (uint32_t)strlen(msg));
            else
                reply(OK, &id, 4);
        }
        else if (cmd == 'd') {
            rd(&id, 4);
            inst_free(&insts[id]);
            reply(OK, NULL, 0);
        }
        else if (cmd == 'r') {
            uint8_t nl, na;
            char name[256];
            int32_t args[8], res[4];
            rd(&id, 4);
            rd(&nl, 1);
            rd(name, nl);
            name[nl] = 0;
            rd(&na, 1);
            rd(args, 4u * na);
            Inst *in = &insts[id];
            wasm_function_inst_t f = wasm_runtime_lookup_function(in->inst, name);
            if (!f) {
                reply(ERR, "no such export", 14);
                continue;
            }
            uint32_t nres = wasm_func_get_result_count(f, in->inst);
            if (call_i32(in, f, na, args, nres, res) != OK) {
                reply(TRAP, msg, (uint32_t)strlen(msg));
                continue;
            }
            uint8_t p[1 + 16];
            p[0] = (uint8_t)nres;
            memcpy(p + 1, res, 4 * nres);
            reply(OK, p, 1 + 4 * nres);
        }
        else if (cmd == 'i') {
            int32_t abi, op;
            uint32_t n;
            rd(&id, 4);
            rd(&abi, 4);
            rd(&op, 4);
            rd(&n, 4);
            uint8_t *data = malloc(n ? n : 1);
            rd(data, n);
            uint8_t *out;
            uint32_t on;
            int s = invoke(&insts[id], abi, op, data, n, &out, &on);
            free(data);
            if (s == OK) {
                reply(OK, out, on);
                free(out);
            }
            else
                reply(s, msg, (uint32_t)strlen(msg));
        }
        else if (cmd == 'm') {
            rd(&id, 4);
            uint32_t len = (uint32_t)mem_len(&insts[id], NULL);
            reply(OK, &len, 4);
        }
        else if (cmd == 'c') {
            uint64_t c[2] = { clock_calls, random_calls };
            reply(OK, c, 16);
        }
        else if (cmd == 'e') {
            char label[128];
            snprintf(label, sizeof label, "wamr 2.4.5 running-mode %s", mode_arg);
            reply(OK, label, (uint32_t)strlen(label));
        }
        else if (cmd == 'q')
            break;
        else {
            reply(ERR, "unknown command", 15);
            break;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "usage: aprv-wamr serve|first|bench MODULE [G5 [JWS]] [--running-mode M]\n");
        return 2;
    }
    const char *cmd = argv[1];
    RunningMode rm = 0;
    for (int i = 1; i + 1 < argc; i++)
        if (!strcmp(argv[i], "--running-mode")) {
            mode_arg = argv[i + 1];
            rm = !strcmp(mode_arg, "interp") ? Mode_Interp
                 : !strcmp(mode_arg, "fast-jit") ? Mode_Fast_JIT
                 : !strcmp(mode_arg, "llvm-jit") ? Mode_LLVM_JIT
                 : !strcmp(mode_arg, "multi-tier") ? Mode_Multi_Tier_JIT
                                                   : 0;
        }
    double t0 = now_ms();
    RuntimeInitArgs init;
    memset(&init, 0, sizeof init);
    init.mem_alloc_type = Alloc_With_System_Allocator;
    init.native_module_name = "aprv";
    init.native_symbols = natives;
    init.n_native_symbols = sizeof natives / sizeof natives[0];
    init.running_mode = rm;
    init.llvm_jit_opt_level = 3; /* iwasm's defaults (product-mini/platforms/posix/main.c) */
    init.llvm_jit_size_level = 3;
    if (rm && !wasm_runtime_is_running_mode_supported(rm)) {
        fprintf(stderr, "aprv-wamr: running mode %s not supported by this libiwasm\n", mode_arg);
        return 2;
    }
    if (!wasm_runtime_full_init(&init)) {
        fprintf(stderr, "aprv-wamr: wasm_runtime_full_init failed\n");
        return 2;
    }
    double init_ms = now_ms() - t0;
    double t1 = now_ms();
    uint32_t wn;
    uint8_t *wasm = read_file(argv[2], &wn); /* must stay alive until unload */
    char err[256];
    module = wasm_runtime_load(wasm, wn, err, sizeof err);
    if (!module) {
        fprintf(stderr, "aprv-wamr: load: %s\n", err);
        return 2;
    }
    double load_ms = now_ms() - t1;

    if (!strcmp(cmd, "serve")) {
        serve();
    }
    else if (!strcmp(cmd, "first") && argc >= 4) {
        uint32_t gn;
        uint8_t *g5 = read_file(argv[3], &gn);
        Inst in;
        double t2 = now_ms();
        if (inst_new(&in) != OK)
            die("instantiate");
        double inst_ms = now_ms() - t2;
        uint8_t *o1, *o2;
        uint32_t n1, n2;
        double t3 = now_ms();
        if (invoke(&in, 1, 1, g5, gn, &o1, &n1) != OK)
            die("first call");
        double first_ms = now_ms() - t3;
        long long first_ns = mono_ns();
        double t4 = now_ms();
        if (invoke(&in, 1, 1, g5, gn, &o2, &n2) != OK)
            die("second call");
        double second_ms = now_ms() - t4;
        printf("{\"engine\":\"wamr 2.4.5\",\"mode\":\"%s\",\"running_mode\":\"%s\",\"init_ms\":%.3f,\"load_ms\":%.3f,"
               "\"instantiate_ms\":%.3f,\"first_call_ms\":%.3f,\"second_call_ms\":%.3f,\"verified\":%s,\"first_result_mono_ns\":%lld,"
               "\"rss_kb\":%ld,\"hwm_kb\":%ld}\n",
               mode_arg, running_mode_name(wasm_runtime_get_running_mode(in.inst)), init_ms, load_ms, inst_ms, first_ms,
               second_ms, verified(o1, n1) && verified(o2, n2) ? "true" : "false", first_ns, proc_status("VmRSS:"),
               proc_status("VmHWM:"));
        fflush(stdout);
        _exit(0); /* the result is out; do not time the JIT threads' teardown */
    }
    else if (!strcmp(cmd, "bench") && argc >= 5) {
        uint32_t gn, jn;
        uint8_t *g5 = read_file(argv[3], &gn), *jws = read_file(argv[4], &jn);
        Inst in;
        double t2 = now_ms();
        if (inst_new(&in) != OK)
            die("instantiate");
        double inst_ms = now_ms() - t2;
        printf("{\"phase\":\"setup\",\"engine\":\"wamr 2.4.5\",\"mode\":\"%s\",\"running_mode\":\"%s\",\"init_ms\":%.3f,"
               "\"load_ms\":%.3f,\"instantiate_ms\":%.3f,\"rss_kb\":%ld}\n",
               mode_arg, running_mode_name(wasm_runtime_get_running_mode(in.inst)), init_ms, load_ms, inst_ms,
               proc_status("VmRSS:"));
        fflush(stdout);
        bench_op(&in, "g5", 1, g5, gn);
        bench_op(&in, "jws", 258, jws, jn);
        printf("{\"phase\":\"end\",\"rss_kb\":%ld,\"hwm_kb\":%ld}\n", proc_status("VmRSS:"), proc_status("VmHWM:"));
        fflush(stdout);
        _exit(0);
    }
    else {
        fprintf(stderr, "aprv-wamr: unknown command %s\n", cmd);
        return 2;
    }
    wasm_runtime_unload(module);
    wasm_runtime_destroy();
    free(wasm);
    return 0;
}
