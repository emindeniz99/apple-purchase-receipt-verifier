/*
 * A NIF shim over the C ABI, for Elixir and any other BEAM language.
 *
 * The BEAM has no FFI of its own. Every native call from Elixir goes through
 * a NIF: a C function the emulator loads and calls directly. So an Elixir
 * consumer of this library needs exactly one piece of C, and this is it:
 * it converts Erlang terms to the arguments in
 * include/apple_purchase_receipt_verifier.h and back, and does nothing else.
 * No verification logic lives here.
 *
 * MEMORY. Two owned things cross the boundary and both are released here.
 *
 *   - The handle from aprv_verifier_new() is stored in an ErlNifResourceType
 *     whose destructor calls aprv_verifier_free(). The garbage collector
 *     runs that destructor when the last Elixir reference to the handle is
 *     dropped, so a caller cannot leak one and cannot free one twice.
 *   - AprvResult.json and the endpoint response are copied into an Erlang
 *     binary and freed with aprv_string_free() before the NIF returns. The
 *     binary the caller receives is the BEAM's, so the Rust allocation never
 *     outlives the call.
 *
 * SCHEDULERS. Verifying a chain is milliseconds of CPU, which is long enough
 * to hurt a BEAM scheduler thread: a NIF that does not return within about a
 * millisecond delays every process on that scheduler. Every call that parses
 * or verifies is therefore ERL_NIF_DIRTY_JOB_CPU_BOUND, which runs it on a
 * dirty scheduler instead.
 *
 * BYTES. An Erlang binary is a length and bytes, and so is the input of the
 * ABI's _bytes calls, which this shim uses: aprv_verify_receipt_bytes,
 * aprv_verify_signed_data_bytes and aprv_verify_receipt_endpoint_bytes.
 * Each binary is passed as it is, without a copy, so a binary holding a NUL
 * or bytes that are not UTF-8 gets the verdict aprv.wasm gives it, as it
 * would from every other host. On a verdict (status below 100) the JSON is
 * the document aprv.wasm answers,
 * {"verified":true,"payload":...,"environment":...} or
 * {"verified":false,"reason":...,"message":...}; on a mistake in the call
 * (100 and above) there is none and the binary handed back is empty.
 *
 * TWO SENTINELS mirror the ABI's own: an empty roots list means "the bundled
 * Apple roots" (NULL, NULL, 0), and a nil clock means "read the system
 * clock" (a NULL clock pointer).
 */

#include <erl_nif.h>
#include <string.h>

#include "apple_purchase_receipt_verifier.h"

/* --- resources ---------------------------------------------------------- */

static ErlNifResourceType *verifier_type = NULL;

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_invalid_argument;
static ERL_NIF_TERM atom_nil;

typedef struct {
  AprvVerifier *handle;
} aprv_resource;

static void destroy_verifier(ErlNifEnv *env, void *object) {
  (void)env;
  aprv_verifier_free(((aprv_resource *)object)->handle);
}

static AprvVerifier *handle_of(ErlNifEnv *env, ERL_NIF_TERM term) {
  aprv_resource *resource = NULL;
  if (!enif_get_resource(env, term, verifier_type, (void **)&resource)) {
    return NULL;
  }
  return resource->handle;
}

/* --- conversions -------------------------------------------------------- */

static ERL_NIF_TERM binary_of(ErlNifEnv *env, const char *text) {
  size_t length = text == NULL ? 0 : strlen(text);
  ERL_NIF_TERM term;
  unsigned char *data = enif_make_new_binary(env, length, &term);
  if (length > 0) {
    memcpy(data, text, length);
  }
  return term;
}

/* `{:ok, json}` on APRV_REASON_OK, `{:error, status, json}` otherwise, with
 * an empty binary when the ABI answered no JSON. The Rust allocation is
 * freed here either way. */
static ERL_NIF_TERM make_result(ErlNifEnv *env, int32_t status, char *json) {
  ERL_NIF_TERM payload = binary_of(env, json);
  aprv_string_free(json);
  if (status == APRV_REASON_OK) {
    return enif_make_tuple2(env, atom_ok, payload);
  }
  return enif_make_tuple3(env, atom_error, enif_make_int(env, status), payload);
}

typedef struct {
  const uint8_t **ders;
  size_t *lens;
  size_t count;
} anchors;

static void anchors_free(anchors *loaded) {
  enif_free((void *)loaded->ders);
  enif_free(loaded->lens);
  loaded->ders = NULL;
  loaded->lens = NULL;
  loaded->count = 0;
}

/* A list of DER binaries as the (ders, lens, count) triple the ABI takes.
 * The bytes stay owned by the terms, which the caller's argument list keeps
 * alive for the whole call; the ABI retains nothing past it. */
static int anchors_load(ErlNifEnv *env, ERL_NIF_TERM list, anchors *loaded) {
  unsigned length = 0;
  loaded->ders = NULL;
  loaded->lens = NULL;
  loaded->count = 0;
  if (!enif_get_list_length(env, list, &length)) {
    return 0;
  }
  if (length == 0) {
    return 1;
  }
  loaded->ders = enif_alloc(length * sizeof(*loaded->ders));
  loaded->lens = enif_alloc(length * sizeof(*loaded->lens));
  if (loaded->ders == NULL || loaded->lens == NULL) {
    anchors_free(loaded);
    return 0;
  }
  ERL_NIF_TERM head;
  ERL_NIF_TERM tail = list;
  size_t index = 0;
  while (enif_get_list_cell(env, tail, &head, &tail)) {
    ErlNifBinary der;
    if (!enif_inspect_binary(env, head, &der)) {
      anchors_free(loaded);
      return 0;
    }
    loaded->ders[index] = der.data;
    loaded->lens[index] = der.size;
    index += 1;
  }
  loaded->count = index;
  return 1;
}

/* --- the verifier ------------------------------------------------------- */

/* `verifier_new(roots, clock)`: `{:ok, verifier}`, or
 * `{:error, :invalid_argument}` for the NULL the ABI returns when it refuses
 * a configuration. */
static ERL_NIF_TERM nif_verifier_new(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  ErlNifSInt64 clock_millis = 0;
  const int64_t *clock = NULL;
  if (!enif_is_identical(argv[1], atom_nil)) {
    if (!enif_get_int64(env, argv[1], &clock_millis)) {
      return enif_make_badarg(env);
    }
    clock = (const int64_t *)&clock_millis;
  }
  anchors roots;
  if (!anchors_load(env, argv[0], &roots)) {
    return enif_make_badarg(env);
  }
  AprvVerifier *handle =
      aprv_verifier_new((const uint8_t *const *)roots.ders, roots.lens, roots.count, clock);
  anchors_free(&roots);
  if (handle == NULL) {
    return enif_make_tuple2(env, atom_error, atom_invalid_argument);
  }
  aprv_resource *resource = enif_alloc_resource(verifier_type, sizeof(aprv_resource));
  if (resource == NULL) {
    aprv_verifier_free(handle);
    return enif_make_tuple2(env, atom_error, atom_invalid_argument);
  }
  resource->handle = handle;
  ERL_NIF_TERM term = enif_make_resource(env, resource);
  /* The term holds the only reference from here on; the GC runs the
   * destructor when it is dropped. */
  enif_release_resource(resource);
  return enif_make_tuple2(env, atom_ok, term);
}

typedef int32_t (*verify_call)(const AprvVerifier *, const uint8_t *, size_t, AprvResult *);

static ERL_NIF_TERM verify(ErlNifEnv *env, const ERL_NIF_TERM argv[], verify_call call) {
  AprvVerifier *verifier = handle_of(env, argv[0]);
  ErlNifBinary input;
  if (verifier == NULL || !enif_inspect_binary(env, argv[1], &input)) {
    return enif_make_badarg(env);
  }
  AprvResult result = {0, NULL};
  call(verifier, input.data, input.size, &result);
  return make_result(env, result.status, result.json);
}

static ERL_NIF_TERM nif_verify_receipt(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  return verify(env, argv, aprv_verify_receipt_bytes);
}

static ERL_NIF_TERM nif_verify_signed_data(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  return verify(env, argv, aprv_verify_signed_data_bytes);
}

/* The endpoint never reports a verdict through the return value: every
 * verdict is the `status` field inside the body it answers, a body that is
 * not UTF-8 or holds a NUL included. A non-zero return means the call itself
 * was malformed, and *response is untouched. */
static ERL_NIF_TERM nif_verify_receipt_endpoint(ErlNifEnv *env, int argc,
                                                const ERL_NIF_TERM argv[]) {
  (void)argc;
  AprvVerifier *verifier = handle_of(env, argv[0]);
  unsigned int environment = 0;
  ErlNifBinary request;
  if (verifier == NULL || !enif_get_uint(env, argv[1], &environment) ||
      !enif_inspect_binary(env, argv[2], &request)) {
    return enif_make_badarg(env);
  }
  char *response = NULL;
  int32_t status = aprv_verify_receipt_endpoint_bytes(verifier, (uint32_t)environment,
                                                      request.data, request.size, &response);
  if (status != APRV_REASON_OK) {
    return enif_make_tuple2(env, atom_error, enif_make_int(env, status));
  }
  ERL_NIF_TERM payload = binary_of(env, response);
  aprv_string_free(response);
  return enif_make_tuple2(env, atom_ok, payload);
}

/* aprv_version returns a static string. Never free it. */
static ERL_NIF_TERM nif_version(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  (void)argv;
  return binary_of(env, aprv_version());
}

/* --- registration ------------------------------------------------------- */

static int load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
  (void)priv_data;
  (void)load_info;
  verifier_type = enif_open_resource_type(env, NULL, "aprv_verifier", destroy_verifier,
                                          ERL_NIF_RT_CREATE, NULL);
  if (verifier_type == NULL) {
    return 1;
  }
  atom_ok = enif_make_atom(env, "ok");
  atom_error = enif_make_atom(env, "error");
  atom_invalid_argument = enif_make_atom(env, "invalid_argument");
  atom_nil = enif_make_atom(env, "nil");
  return 0;
}

/* Everything that parses is dirty: the constructor reads DER certificates
 * and the verify calls walk a chain and check a signature. */
static ErlNifFunc funcs[] = {
    {"version", 0, nif_version, 0},
    {"verifier_new", 2, nif_verifier_new, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_receipt", 2, nif_verify_receipt, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_signed_data", 2, nif_verify_signed_data, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_receipt_endpoint", 3, nif_verify_receipt_endpoint, ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(Elixir.AppleReceiptExample.Native, funcs, load, NULL, NULL, NULL)
