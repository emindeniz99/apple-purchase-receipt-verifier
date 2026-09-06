// The whole C ABI on one page: a StoreKit 2 transaction verified against the
// fixture root that signed it, and the genuine sandbox receipt verified
// against the three bundled Apple roots.
//
//   ./aprv_example <root.der> <transaction.jws> <receipt.b64>
//
// with, from the repository root: fixtures/generated/jws-root.der,
// fixtures/generated/transaction.jws and
// fixtures/generated/receipt-b64/01-genuine.txt

#include "apple_purchase_receipt_verifier.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

static std::string read(const char *path) {
  std::ifstream file(path, std::ios::binary);
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

static int show(const char *what, AprvResult result) {
  std::cout << what << ": status " << result.status << "\n"
            << (result.json == nullptr ? "" : result.json) << "\n\n";
  aprv_string_free(result.json);
  return result.status == APRV_REASON_OK ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc != 4) {
    std::cerr << "usage: " << argv[0] << " <root.der> <transaction.jws> <receipt.b64>\n";
    return 2;
  }
  std::cout << "apple-purchase-receipt-verifier " << aprv_version() << "\n\n";
  const std::string root = read(argv[1]);
  const std::string jws = read(argv[2]);
  const std::string receipt = read(argv[3]);
  int failures = 0;

  const uint8_t *ders[] = {reinterpret_cast<const uint8_t *>(root.data())};
  const size_t lens[] = {root.size()};
  AprvJwsVerifier *jws_verifier = aprv_verifier_new_jws_with_roots(
      "com.example.app", APRV_ENVIRONMENT_SANDBOX, 0, 0, ders, lens, 1);
  AprvResult transaction = {0, nullptr};
  aprv_verify_transaction(jws_verifier, jws.c_str(), &transaction);
  failures += show("transaction", transaction);
  aprv_verifier_free_jws(jws_verifier);

  AprvReceiptVerifier *receipt_verifier = aprv_verifier_new_receipt("dev.bonzer.weeka.app");
  AprvResult app_receipt = {0, nullptr};
  aprv_verify_receipt_base64(receipt_verifier, receipt.c_str(), &app_receipt);
  failures += show("receipt", app_receipt);
  aprv_verifier_free_receipt(receipt_verifier);

  return failures == 0 ? 0 : 1;
}
