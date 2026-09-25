/* SWIG interface for the apple-purchase-receipt-verifier C ABI.
 *
 * Design: expose the C ABI's opaque handles and free functions directly
 * (via %include of the unmodified header at the bottom), and add a small
 * set of %inline C helpers for every verification call. Each helper:
 *   - takes Java-friendly arguments (byte[], byte[][], String) via the
 *     custom typemaps below, instead of raw pointer+length pairs;
 *   - returns the ABI's json (success payload OR the {"reason","message"}
 *     error body) as a %newobject char*, freed via aprv_string_free()
 *     through the global `newfree` typemap the moment SWIG has copied it
 *     into a Java String — so the JNI call never leaks or double-frees;
 *   - reports the numeric AprvReason through an `int[1]` out-parameter
 *     (SWIG's typemaps.i OUTPUT convention), so one call carries both
 *     status and json without a hand-rolled struct typemap.
 *
 * No verification logic lives here: every helper is a direct, unconditional
 * pass-through to one aprv_* call plus the ownership/marshalling glue.
 * bakeoff/swig/*.java (the hand-written layer) decides what a nonzero
 * status means.
 */
%module(package="bakeoff.swig.raw") aprv

%{
#include "apple_purchase_receipt_verifier.h"
#include <stdlib.h>
%}

%include "stdint.i"
%include "exception.i"
%include "typemaps.i"

/* ---- ownership: every char* this module hands back as a %newobject is
   the ABI's own allocation; hand it back the instant SWIG has copied it
   into a Java String. Never applies to aprv_version()'s return (not
   %newobject) or to any pointer we did not allocate. */
%typemap(newfree) char * "aprv_string_free($1);";

/* ---- status out-parameter: `int *out_status` becomes a trailing
   `int[] out_status` argument in Java; the helper writes out_status[0]. */
%apply int *OUTPUT { int *out_status };
%apply int *OUTPUT { int *out_rc };

/* ---- a single byte[] mapped to (const uint8_t *, size_t) ------------- */
%typemap(jni)    (const uint8_t *BYTES, size_t BYTES_LEN) "jbyteArray"
%typemap(jtype)  (const uint8_t *BYTES, size_t BYTES_LEN) "byte[]"
%typemap(jstype) (const uint8_t *BYTES, size_t BYTES_LEN) "byte[]"
%typemap(javain) (const uint8_t *BYTES, size_t BYTES_LEN) "$javainput"
%typemap(in)     (const uint8_t *BYTES, size_t BYTES_LEN) {
  $1 = $input ? (uint8_t *) (*jenv)->GetByteArrayElements(jenv, $input, 0) : NULL;
  $2 = $input ? (size_t) (*jenv)->GetArrayLength(jenv, $input) : 0;
}
%typemap(freearg) (const uint8_t *BYTES, size_t BYTES_LEN) {
  if ($input && $1) (*jenv)->ReleaseByteArrayElements(jenv, $input, (jbyte *) $1, JNI_ABORT);
}
%apply (const uint8_t *BYTES, size_t BYTES_LEN) {
  (const uint8_t *der,  size_t len),
  (const uint8_t *guid, size_t guid_len)
}

/* ---- a byte[][] of DER roots mapped to (ders, lens, count) ----------- */
%typemap(jni)    (const uint8_t *const *ROOTS, const size_t *ROOTS_LEN, size_t ROOTS_COUNT) "jobjectArray"
%typemap(jtype)  (const uint8_t *const *ROOTS, const size_t *ROOTS_LEN, size_t ROOTS_COUNT) "byte[][]"
%typemap(jstype) (const uint8_t *const *ROOTS, const size_t *ROOTS_LEN, size_t ROOTS_COUNT) "byte[][]"
%typemap(javain) (const uint8_t *const *ROOTS, const size_t *ROOTS_LEN, size_t ROOTS_COUNT) "$javainput"
%typemap(in)     (const uint8_t *const *ROOTS, const size_t *ROOTS_LEN, size_t ROOTS_COUNT) {
  if ($input == NULL) {
    $1 = NULL; $2 = NULL; $3 = 0;
  } else {
    jsize n = (*jenv)->GetArrayLength(jenv, $input);
    uint8_t **ptrs = (uint8_t **) malloc(sizeof(uint8_t *) * (n > 0 ? (size_t) n : 1));
    size_t   *lens = (size_t *)   malloc(sizeof(size_t)    * (n > 0 ? (size_t) n : 1));
    jsize i;
    for (i = 0; i < n; i++) {
      jbyteArray el = (jbyteArray) (*jenv)->GetObjectArrayElement(jenv, $input, i);
      lens[i] = (size_t) (*jenv)->GetArrayLength(jenv, el);
      ptrs[i] = (uint8_t *) (*jenv)->GetByteArrayElements(jenv, el, 0);
      (*jenv)->DeleteLocalRef(jenv, el);
    }
    $1 = (const uint8_t *const *) ptrs;
    $2 = (const size_t *) lens;
    $3 = (size_t) n;
  }
}
%typemap(freearg) (const uint8_t *const *ROOTS, const size_t *ROOTS_LEN, size_t ROOTS_COUNT) {
  if ($1) {
    jsize n = (*jenv)->GetArrayLength(jenv, $input);
    uint8_t **ptrs = (uint8_t **) $1;
    jsize i;
    for (i = 0; i < n; i++) {
      jbyteArray el = (jbyteArray) (*jenv)->GetObjectArrayElement(jenv, $input, i);
      (*jenv)->ReleaseByteArrayElements(jenv, el, (jbyte *) ptrs[i], JNI_ABORT);
      (*jenv)->DeleteLocalRef(jenv, el);
    }
    free((void *) $1);
    free((void *) $2);
  }
}
%apply (const uint8_t *const *ROOTS, const size_t *ROOTS_LEN, size_t ROOTS_COUNT) {
  (const uint8_t *const *ders, const size_t *lens, size_t count)
}

/* ---- constructors: throw IllegalArgumentException instead of NULL ---- */
%exception jws_new {
  $action
  if (!result) SWIG_exception(SWIG_ValueError, "rejected JWS verifier configuration (bundle id, environment mask, app apple id, or root certificates)");
}
%exception receipt_new {
  $action
  if (!result) SWIG_exception(SWIG_ValueError, "rejected receipt verifier configuration (bundle id or root certificates)");
}
%exception endpoint_new {
  $action
  if (!result) SWIG_exception(SWIG_ValueError, "rejected endpoint configuration (environment or root certificates)");
}

%inline %{

/* bundle_id/envs/app_apple_id as in aprv_verifier_new_jws*; roots == NULL
   selects the three bundled Apple roots, matching the ABI's own NULL
   convention. */
AprvJwsVerifier *jws_new(const char *bundle_id, uint32_t envs, uint64_t app_apple_id,
                          const uint8_t *const *ders, const size_t *lens, size_t count) {
    return (ders == NULL)
        ? aprv_verifier_new_jws(bundle_id, envs, app_apple_id)
        : aprv_verifier_new_jws_with_roots(bundle_id, envs, app_apple_id, ders, lens, count);
}

AprvReceiptVerifier *receipt_new(const char *bundle_id,
                                  const uint8_t *const *ders, const size_t *lens, size_t count) {
    return (ders == NULL)
        ? aprv_verifier_new_receipt(bundle_id)
        : aprv_verifier_new_receipt_with_roots(bundle_id, ders, lens, count);
}

AprvReceiptEndpoint *endpoint_new(uint32_t environment,
                                   const uint8_t *const *ders, const size_t *lens, size_t count) {
    return (ders == NULL)
        ? aprv_endpoint_new(environment)
        : aprv_endpoint_new_with_roots(environment, ders, lens, count);
}

%}

%newobject jws_verify_transaction;
%newobject receipt_verify_der;
%newobject receipt_verify_der_with_guid;
%newobject receipt_verify_base64;
%newobject receipt_verify_base64_with_guid;
%newobject endpoint_verify_json;

%inline %{

/* Every *_verify_* helper below: writes *out_status (an AprvReason) and
   returns the json the ABI produced — the verified payload on status==0,
   or {"reason":"<TOKEN>","message":"<detail>"} otherwise. Never NULL
   unless the allocation itself failed. No verdict is made here; the
   Java layer reads out_status and the "reason" token. */

char *jws_verify_transaction(const AprvJwsVerifier *v, const char *jws, int *out_status) {
    AprvResult r = {0, NULL};
    *out_status = aprv_verify_transaction(v, jws, &r);
    return r.json;
}

char *receipt_verify_der(const AprvReceiptVerifier *v, const uint8_t *der, size_t len, int *out_status) {
    AprvResult r = {0, NULL};
    *out_status = aprv_verify_receipt_der(v, der, len, &r);
    return r.json;
}

char *receipt_verify_der_with_guid(const AprvReceiptVerifier *v, const uint8_t *der, size_t len,
                                    const uint8_t *guid, size_t guid_len, int *out_status) {
    AprvResult r = {0, NULL};
    *out_status = aprv_verify_receipt_der_with_device_guid(v, der, len, guid, guid_len, &r);
    return r.json;
}

char *receipt_verify_base64(const AprvReceiptVerifier *v, const char *b64, int *out_status) {
    AprvResult r = {0, NULL};
    *out_status = aprv_verify_receipt_base64(v, b64, &r);
    return r.json;
}

char *receipt_verify_base64_with_guid(const AprvReceiptVerifier *v, const char *b64,
                                       const uint8_t *guid, size_t guid_len, int *out_status) {
    AprvResult r = {0, NULL};
    *out_status = aprv_verify_receipt_base64_with_device_guid(v, b64, guid, guid_len, &r);
    return r.json;
}

/* out_rc is the ABI's raw int32_t return: 0 means the call itself was
   well-formed (a verdict, success or failure, is inside the returned
   JSON's "status" field); nonzero means the call was malformed (null
   argument, non-UTF-8 body) and the return is NULL. */
char *endpoint_verify_json(const AprvReceiptEndpoint *e, const char *request_json, int *out_rc) {
    char *resp = NULL;
    *out_rc = aprv_verify_receipt_endpoint_json(e, request_json, &resp);
    return resp;
}

%}

/* Opaque handle types, free functions, and aprv_version() come straight
   from the unmodified ABI header — no ownership subtlety: the frees
   return void and aprv_version()'s string is static and never freed. */
%include "apple_purchase_receipt_verifier.h"
