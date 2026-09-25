%module aprv
%{
#include "apple_purchase_receipt_verifier.h"
%}
%include "stdint.i"

/* Ownership: every char* the ABI hands out belongs to Rust and must go
   back through aprv_string_free. SWIG copies it into a Python str, then
   the newfree typemap frees the original. */
%typemap(newfree) char * "aprv_string_free($1);";

/* Hide the raw AprvResult out-parameter behind one call that returns the
   JSON and frees it; errors become a Python exception. */
%newobject verify_receipt_base64;
%exception verify_receipt_base64 {
    $action
    if (!result) { PyErr_SetString(PyExc_ValueError, "receipt rejected (see aprv_last_error)"); SWIG_fail; }
}
%inline %{
char *verify_receipt_base64(const AprvReceiptVerifier *v, const char *b64) {
    AprvResult r = {0, 0};
    int32_t status = aprv_verify_receipt_base64(v, b64, &r);
    if (status != 0) { aprv_string_free(r.json); return NULL; }
    return r.json;
}
%}

%include "apple_purchase_receipt_verifier.h"
