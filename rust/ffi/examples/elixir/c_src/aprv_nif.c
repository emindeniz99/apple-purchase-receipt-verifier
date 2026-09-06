/*
 * A NIF shim over the C ABI, for Elixir and any other BEAM language.
 *
 * The BEAM has no FFI of its own. Every native call from Elixir goes through
 * a NIF: a C function the emulator loads and calls directly. So an Elixir
 * consumer of this library needs exactly one piece of C, and this is it —
 * it converts Erlang terms to the arguments in
 * include/apple_purchase_receipt_verifier.h and back, and does nothing else.
 * No verification logic lives here.
 *
 * MEMORY. Two owned things cross the boundary and both are released here.
 *
 *   - A handle from aprv_*_new*() is stored in an ErlNifResourceType whose
 *     destructor calls the matching aprv_*_free(). The garbage collector
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
 * STRINGS. The ABI takes NUL-terminated char *; an Erlang binary is a length
 * and bytes. Each one is copied into a NUL-terminated buffer for the call,
 * so a binary holding an embedded NUL is truncated at it, exactly as it
 * would be for a C caller.
 *
 * TWO SENTINELS keep the shim at nine functions instead of nineteen. An
 * empty roots list means "the bundled Apple roots", so one NIF covers both
 * aprv_*_new and aprv_*_new_with_roots; an empty device GUID means "do not
 * check the device hash", so one NIF covers each receipt call and its
 * _with_device_guid variant. Every one of the nineteen exports is still
 * reached.
 */

#include <erl_nif.h>
#include <string.h>

#include "apple_purchase_receipt_verifier.h"

/* --- resources ---------------------------------------------------------- */

static ErlNifResourceType *jws_verifier_type = NULL;
static ErlNifResourceType *receipt_verifier_type = NULL;
static ErlNifResourceType *endpoint_type = NULL;

static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_invalid_argument;

typedef struct {
  void *handle;
} aprv_resource;

static void free_jws(void *handle) { aprv_verifier_free_jws((AprvJwsVerifier *)handle); }

static void free_receipt(void *handle) {
  aprv_verifier_free_receipt((AprvReceiptVerifier *)handle);
}

static void free_endpoint(void *handle) { aprv_endpoint_free((AprvReceiptEndpoint *)handle); }

static void destroy_jws(ErlNifEnv *env, void *object) {
  (void)env;
  free_jws(((aprv_resource *)object)->handle);
}

static void destroy_receipt(ErlNifEnv *env, void *object) {
  (void)env;
  free_receipt(((aprv_resource *)object)->handle);
}

static void destroy_endpoint(ErlNifEnv *env, void *object) {
  (void)env;
  free_endpoint(((aprv_resource *)object)->handle);
}

/* `{:ok, resource}`, or `{:error, :invalid_argument}` for the NULL the ABI
 * returns when it refuses a configuration. */
static ERL_NIF_TERM wrap_handle(ErlNifEnv *env, ErlNifResourceType *type, void *handle,
                                void (*release)(void *)) {
  if (handle == NULL) {
    return enif_make_tuple2(env, atom_error, atom_invalid_argument);
  }
  aprv_resource *resource = enif_alloc_resource(type, sizeof(aprv_resource));
  if (resource == NULL) {
    release(handle);
    return enif_make_tuple2(env, atom_error, atom_invalid_argument);
  }
  resource->handle = handle;
  ERL_NIF_TERM term = enif_make_resource(env, resource);
  /* The term holds the only reference from here on; the GC runs the
   * destructor when it is dropped. */
  enif_release_resource(resource);
  return enif_make_tuple2(env, atom_ok, term);
}

static void *handle_of(ErlNifEnv *env, ERL_NIF_TERM term, ErlNifResourceType *type) {
  aprv_resource *resource = NULL;
  if (!enif_get_resource(env, term, type, (void **)&resource)) {
    return NULL;
  }
  return resource->handle;
}

/* --- conversions -------------------------------------------------------- */

/* A NUL-terminated copy of a binary, released with enif_free. */
static char *cstring(ErlNifEnv *env, ERL_NIF_TERM term) {
  ErlNifBinary binary;
  if (!enif_inspect_binary(env, term, &binary)) {
    return NULL;
  }
  char *copy = enif_alloc(binary.size + 1);
  if (copy == NULL) {
    return NULL;
  }
  memcpy(copy, binary.data, binary.size);
  copy[binary.size] = '\0';
  return copy;
}

static ERL_NIF_TERM binary_of(ErlNifEnv *env, const char *text) {
  size_t length = text == NULL ? 0 : strlen(text);
  ERL_NIF_TERM term;
  unsigned char *data = enif_make_new_binary(env, length, &term);
  if (length > 0) {
    memcpy(data, text, length);
  }
  return term;
}

/* `{:ok, json}` on APRV_REASON_OK, `{:error, status, json}` otherwise. The
 * Rust allocation is freed here either way. */
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

/* --- constructors ------------------------------------------------------- */

static ERL_NIF_TERM nif_jws_verifier_new(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  unsigned int environments = 0;
  ErlNifUInt64 app_apple_id = 0;
  ErlNifUInt64 max_signed_age_secs = 0;
  if (!enif_get_uint(env, argv[1], &environments) ||
      !enif_get_uint64(env, argv[2], &app_apple_id) ||
      !enif_get_uint64(env, argv[3], &max_signed_age_secs)) {
    return enif_make_badarg(env);
  }
  char *bundle_id = cstring(env, argv[0]);
  if (bundle_id == NULL) {
    return enif_make_badarg(env);
  }
  anchors roots;
  if (!anchors_load(env, argv[4], &roots)) {
    enif_free(bundle_id);
    return enif_make_badarg(env);
  }
  AprvJwsVerifier *handle =
      roots.count == 0
          ? aprv_verifier_new_jws(bundle_id, (uint32_t)environments, app_apple_id,
                                  max_signed_age_secs)
          : aprv_verifier_new_jws_with_roots(bundle_id, (uint32_t)environments, app_apple_id,
                                             max_signed_age_secs,
                                             (const uint8_t *const *)roots.ders, roots.lens,
                                             roots.count);
  anchors_free(&roots);
  enif_free(bundle_id);
  return wrap_handle(env, jws_verifier_type, handle, free_jws);
}

static ERL_NIF_TERM nif_receipt_verifier_new(ErlNifEnv *env, int argc,
                                             const ERL_NIF_TERM argv[]) {
  (void)argc;
  char *bundle_id = cstring(env, argv[0]);
  if (bundle_id == NULL) {
    return enif_make_badarg(env);
  }
  anchors roots;
  if (!anchors_load(env, argv[1], &roots)) {
    enif_free(bundle_id);
    return enif_make_badarg(env);
  }
  AprvReceiptVerifier *handle =
      roots.count == 0 ? aprv_verifier_new_receipt(bundle_id)
                       : aprv_verifier_new_receipt_with_roots(
                             bundle_id, (const uint8_t *const *)roots.ders, roots.lens,
                             roots.count);
  anchors_free(&roots);
  enif_free(bundle_id);
  return wrap_handle(env, receipt_verifier_type, handle, free_receipt);
}

static ERL_NIF_TERM nif_endpoint_new(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  unsigned int environment = 0;
  if (!enif_get_uint(env, argv[0], &environment)) {
    return enif_make_badarg(env);
  }
  anchors roots;
  if (!anchors_load(env, argv[1], &roots)) {
    return enif_make_badarg(env);
  }
  AprvReceiptEndpoint *handle =
      roots.count == 0
          ? aprv_endpoint_new((uint32_t)environment)
          : aprv_endpoint_new_with_roots((uint32_t)environment,
                                         (const uint8_t *const *)roots.ders, roots.lens,
                                         roots.count);
  anchors_free(&roots);
  return wrap_handle(env, endpoint_type, handle, free_endpoint);
}

/* --- verification ------------------------------------------------------- */

typedef int32_t (*jws_call)(const AprvJwsVerifier *, const char *, AprvResult *);

static ERL_NIF_TERM verify_jws(ErlNifEnv *env, const ERL_NIF_TERM argv[], jws_call call) {
  AprvJwsVerifier *verifier = handle_of(env, argv[0], jws_verifier_type);
  if (verifier == NULL) {
    return enif_make_badarg(env);
  }
  char *jws = cstring(env, argv[1]);
  if (jws == NULL) {
    return enif_make_badarg(env);
  }
  AprvResult result = {0, NULL};
  call(verifier, jws, &result);
  enif_free(jws);
  return make_result(env, result.status, result.json);
}

static ERL_NIF_TERM nif_verify_transaction(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  return verify_jws(env, argv, aprv_verify_transaction);
}

static ERL_NIF_TERM nif_verify_app_transaction(ErlNifEnv *env, int argc,
                                               const ERL_NIF_TERM argv[]) {
  (void)argc;
  return verify_jws(env, argv, aprv_verify_app_transaction);
}

static ERL_NIF_TERM nif_verify_raw(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  return verify_jws(env, argv, aprv_verify_raw);
}

static ERL_NIF_TERM nif_verify_receipt_der(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
  (void)argc;
  AprvReceiptVerifier *verifier = handle_of(env, argv[0], receipt_verifier_type);
  ErlNifBinary der;
  ErlNifBinary guid;
  if (verifier == NULL || !enif_inspect_binary(env, argv[1], &der) ||
      !enif_inspect_binary(env, argv[2], &guid)) {
    return enif_make_badarg(env);
  }
  AprvResult result = {0, NULL};
  if (guid.size == 0) {
    aprv_verify_receipt_der(verifier, der.data, der.size, &result);
  } else {
    aprv_verify_receipt_der_with_device_guid(verifier, der.data, der.size, guid.data, guid.size,
                                             &result);
  }
  return make_result(env, result.status, result.json);
}

static ERL_NIF_TERM nif_verify_receipt_base64(ErlNifEnv *env, int argc,
                                              const ERL_NIF_TERM argv[]) {
  (void)argc;
  AprvReceiptVerifier *verifier = handle_of(env, argv[0], receipt_verifier_type);
  ErlNifBinary guid;
  if (verifier == NULL || !enif_inspect_binary(env, argv[2], &guid)) {
    return enif_make_badarg(env);
  }
  char *receipt = cstring(env, argv[1]);
  if (receipt == NULL) {
    return enif_make_badarg(env);
  }
  AprvResult result = {0, NULL};
  if (guid.size == 0) {
    aprv_verify_receipt_base64(verifier, receipt, &result);
  } else {
    aprv_verify_receipt_base64_with_device_guid(verifier, receipt, guid.data, guid.size, &result);
  }
  enif_free(receipt);
  return make_result(env, result.status, result.json);
}

/* The endpoint never reports a verdict through the return value: every
 * verdict is the `status` field inside the body it answers. A non-zero
 * return means the call itself was malformed, and *response is untouched. */
static ERL_NIF_TERM nif_verify_receipt_endpoint_json(ErlNifEnv *env, int argc,
                                                     const ERL_NIF_TERM argv[]) {
  (void)argc;
  AprvReceiptEndpoint *endpoint = handle_of(env, argv[0], endpoint_type);
  if (endpoint == NULL) {
    return enif_make_badarg(env);
  }
  char *request = cstring(env, argv[1]);
  if (request == NULL) {
    return enif_make_badarg(env);
  }
  char *response = NULL;
  int32_t status = aprv_verify_receipt_endpoint_json(endpoint, request, &response);
  enif_free(request);
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
  jws_verifier_type = enif_open_resource_type(env, NULL, "aprv_jws_verifier", destroy_jws,
                                              ERL_NIF_RT_CREATE, NULL);
  receipt_verifier_type = enif_open_resource_type(env, NULL, "aprv_receipt_verifier",
                                                  destroy_receipt, ERL_NIF_RT_CREATE, NULL);
  endpoint_type = enif_open_resource_type(env, NULL, "aprv_receipt_endpoint", destroy_endpoint,
                                          ERL_NIF_RT_CREATE, NULL);
  if (jws_verifier_type == NULL || receipt_verifier_type == NULL || endpoint_type == NULL) {
    return 1;
  }
  atom_ok = enif_make_atom(env, "ok");
  atom_error = enif_make_atom(env, "error");
  atom_invalid_argument = enif_make_atom(env, "invalid_argument");
  return 0;
}

/* Everything that parses is dirty: the constructors read DER certificates
 * and the verify calls walk a chain and check a signature. */
static ErlNifFunc funcs[] = {
    {"version", 0, nif_version, 0},
    {"jws_verifier_new", 5, nif_jws_verifier_new, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"receipt_verifier_new", 2, nif_receipt_verifier_new, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"endpoint_new", 2, nif_endpoint_new, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_transaction", 2, nif_verify_transaction, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_app_transaction", 2, nif_verify_app_transaction, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_raw", 2, nif_verify_raw, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_receipt_der", 3, nif_verify_receipt_der, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_receipt_base64", 3, nif_verify_receipt_base64, ERL_NIF_DIRTY_JOB_CPU_BOUND},
    {"verify_receipt_endpoint_json", 2, nif_verify_receipt_endpoint_json,
     ERL_NIF_DIRTY_JOB_CPU_BOUND},
};

ERL_NIF_INIT(Elixir.AppleReceiptExample.Native, funcs, load, NULL, NULL, NULL)
