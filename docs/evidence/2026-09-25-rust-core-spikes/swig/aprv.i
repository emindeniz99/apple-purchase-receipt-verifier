/* One interface file for every SWIG target language. */
%module aprv
%{
#include "apple_purchase_receipt_verifier.h"
%}
%include "stdint.i"
%include "exception.i"

/* Ownership: every char* the ABI returns is Rust's; hand it back. */
%typemap(newfree) char * "aprv_string_free($1);";

/* One call that returns the JSON and frees it; failure becomes the
   target language's own exception (language-neutral SWIG_exception). */
%newobject verify_receipt_base64;
%exception verify_receipt_base64 {
    $action
    if (!result) { SWIG_exception(SWIG_ValueError, "receipt rejected"); }
}
%inline %{
char *verify_receipt_base64(const AprvReceiptVerifier *v, const char *b64) {
    AprvResult r = {0, 0};
    if (aprv_verify_receipt_base64(v, b64, &r) != 0) { aprv_string_free(r.json); return NULL; }
    return r.json;
}
%}
%include "apple_purchase_receipt_verifier.h"
