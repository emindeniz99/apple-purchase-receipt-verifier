// The whole C ABI on one page: a StoreKit 2 transaction verified against the
// fixture root that signed it, the genuine sandbox receipt verified against
// the three bundled Apple roots, and a verifier from init's JSON reporting what
// a host monitors about revocation.
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

  // A verifier pinned to the fixture root, and one on the bundled Apple
  // roots. A NULL clock reads the system clock.
  const uint8_t *ders[] = {reinterpret_cast<const uint8_t *>(root.data())};
  const size_t lens[] = {root.size()};
  AprvVerifier *fixture_verifier = aprv_verifier_new(ders, lens, 1, nullptr);
  AprvResult transaction = {0, nullptr};
  aprv_verify_signed_data(fixture_verifier, jws.c_str(), &transaction);
  failures += show("transaction", transaction);
  aprv_verifier_free(fixture_verifier);

  AprvVerifier *apple_verifier = aprv_verifier_new(nullptr, nullptr, 0, nullptr);
  AprvResult app_receipt = {0, nullptr};
  aprv_verify_receipt(apple_verifier, receipt.c_str(), &app_receipt);
  failures += show("receipt", app_receipt);
  aprv_verifier_free(apple_verifier);

  // Revocation settings arrive as the JSON aprv.wasm's init takes:
  // {"revocation_lists":[...],"revocation_issuers":[...],"distrust":[...]}.
  // `{}` is the bundled roots with no setting, which still reports Apple's lists.
  const std::string config = "{}";
  AprvVerifier *configured = nullptr;
  AprvResult refusal = {0, nullptr};
  if (aprv_verifier_new_config(reinterpret_cast<const uint8_t *>(config.data()), config.size(), nullptr,
                               &configured, &refusal) != APRV_REASON_OK) {
    show("configuration", refusal);
    return 1;
  }
  char *urls = nullptr;
  char *valid_until = nullptr;
  aprv_verifier_revocation_urls(configured, &urls);
  aprv_verifier_revocation_valid_until_ms(configured, &valid_until);
  std::cout << "revocation urls: " << (urls == nullptr ? "" : urls) << "\n"
            << "revocation valid until: " << (valid_until == nullptr ? "" : valid_until) << "\n";
  aprv_string_free(urls);
  aprv_string_free(valid_until);
  aprv_verifier_free(configured);

  return failures == 0 ? 0 : 1;
}
