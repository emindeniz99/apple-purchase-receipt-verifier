/* Spike only (task 3). Why does a library's CMS_SignerInfo_verify refuse a
 * SignerInfo? Parses one DER CMS file, picks the embedded certificate the
 * first SignerInfo names, verifies the signature over the signed
 * attributes and prints the library's error queue. No chain, no store.
 *   cc cms-probe.c -I<inst>/include <inst>/lib/libcrypto.a -lpthread -o cms-probe
 *   ./cms-probe <file.der>
 */
#include <stdio.h>
#include <stdlib.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/crypto.h>

int main(int argc, char **argv) {
  if (argc != 2) return 2;
  FILE *f = fopen(argv[1], "rb");
  if (!f) return 2;
  static unsigned char buf[1 << 20];
  long n = (long)fread(buf, 1, sizeof buf, f);
  fclose(f);
  const unsigned char *p = buf;
  printf("library: %s\n", OpenSSL_version(OPENSSL_VERSION));
  CMS_ContentInfo *cms = d2i_CMS_ContentInfo(NULL, &p, n);
  if (!cms) { printf("d2i_CMS_ContentInfo failed\n"); ERR_print_errors_fp(stdout); return 1; }
  CMS_SignerInfo *si = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
  X509_ALGOR *dig = NULL, *sig = NULL;
  CMS_SignerInfo_get0_algs(si, NULL, NULL, &dig, &sig);
  char oid[128];
  OBJ_obj2txt(oid, sizeof oid, dig->algorithm, 1); printf("digestAlgorithm: %s\n", oid);
  OBJ_obj2txt(oid, sizeof oid, sig->algorithm, 1); printf("signatureAlgorithm: %s\n", oid);
  STACK_OF(X509) *certs = CMS_get1_certs(cms);
  X509 *signer = NULL;
  for (int i = 0; i < sk_X509_num(certs); i++)
    if (CMS_SignerInfo_cert_cmp(si, sk_X509_value(certs, i)) == 0) signer = sk_X509_value(certs, i);
  if (!signer) { printf("signer not found\n"); return 1; }
  CMS_SignerInfo_set1_signer_cert(si, signer);
  int r = CMS_SignerInfo_verify(si);
  printf("CMS_SignerInfo_verify: %d\n", r);
  ERR_print_errors_fp(stdout);
  return r == 1 ? 0 : 1;
}
