// Drives fixtures/cases.json — the normative cross-language conformance
// vectors — through the C ABI, from C++17, with no dependencies at all.
//
//   node tools/gen-cases-manifest.mjs <dir>
//   ./aprv_conformance <dir>
//
// This is the primary harness for the ABI: a passing run is the evidence
// that the compiled-toolchain path works end to end — the header compiles as
// C++, the symbols link, the calls return what the vectors say, and every
// string handed out is freed.
//
// It carries no case-specific knowledge. The generator resolved fixture ids
// to files, checked their digests, decoded the codecs, computed the
// environment bitmask and wrote out the endpoint request bodies, because a
// dependency-free C++ program can do none of those. What is left here is the
// part that has to be C: build a verifier from the generic config, dispatch
// on the operation, compare the status, and read a few top-level fields off
// the JSON the ABI returned.
//
// The JSON reader below is a top-level scalar extractor and nothing more —
// no vendored parser, and no ambition to become one. Nested paths
// (`receipt.bundle_id`, `inAppPurchases[productId=x].quantity`) are checked
// by rust/ffi/tests/conformance.py, which has Python's json; the manifest
// counts every one it dropped and this program prints the total, so the gap
// is a number on the screen rather than a silence.

#include "apple_purchase_receipt_verifier.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <string>
#include <vector>

namespace {

// --- the manifest --------------------------------------------------------

struct Case {
  std::vector<std::pair<std::string, std::string>> entries;

  bool has(const std::string &key) const {
    for (const auto &entry : entries) {
      if (entry.first == key) return true;
    }
    return false;
  }

  std::string get(const std::string &key, const std::string &fallback = "") const {
    for (const auto &entry : entries) {
      if (entry.first == key) return entry.second;
    }
    return fallback;
  }

  std::vector<std::string> all(const std::string &key) const {
    std::vector<std::string> found;
    for (const auto &entry : entries) {
      if (entry.first == key) found.push_back(entry.second);
    }
    return found;
  }
};

std::vector<std::string> split(const std::string &text, char separator) {
  std::vector<std::string> parts;
  std::string current;
  for (char c : text) {
    if (c == separator) {
      parts.push_back(current);
      current.clear();
    } else {
      current.push_back(c);
    }
  }
  parts.push_back(current);
  return parts;
}

bool read_file(const std::string &path, std::vector<unsigned char> &out) {
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return false;
  out.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>());
  return true;
}

// --- a top-level JSON field reader ---------------------------------------

// The raw text of the value `"key"` maps to at the top level of `json`, or
// an empty optional-ish `found=false`. Depth tracking is what makes it
// top-level: a `bundleId` nested inside a claim object must not answer a
// query about the document's own `bundleId`.
bool top_level_value(const std::string &json, const std::string &key, std::string &out) {
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  size_t index = 0;
  const std::string quoted = "\"" + key + "\"";

  while (index < json.size()) {
    char c = json[index];
    if (in_string) {
      if (escaped) {
        escaped = false;
      } else if (c == '\\') {
        escaped = true;
      } else if (c == '"') {
        in_string = false;
      }
      index += 1;
      continue;
    }
    if (c == '"') {
      // A key of the top-level object starts here only at depth 1.
      if (depth == 1 && json.compare(index, quoted.size(), quoted) == 0) {
        size_t after = index + quoted.size();
        while (after < json.size() && (json[after] == ' ' || json[after] == '\t')) after += 1;
        if (after < json.size() && json[after] == ':') {
          after += 1;
          while (after < json.size() && (json[after] == ' ' || json[after] == '\t')) after += 1;
          // Walk the value: a string, or anything up to the comma or the
          // closing brace at this depth.
          size_t start = after;
          int value_depth = 0;
          bool value_string = false;
          bool value_escaped = false;
          size_t cursor = after;
          while (cursor < json.size()) {
            char v = json[cursor];
            if (value_string) {
              if (value_escaped) {
                value_escaped = false;
              } else if (v == '\\') {
                value_escaped = true;
              } else if (v == '"') {
                value_string = false;
                if (value_depth == 0) {
                  cursor += 1;
                  break;
                }
              }
              cursor += 1;
              continue;
            }
            if (v == '"') {
              value_string = true;
              cursor += 1;
              continue;
            }
            if (v == '{' || v == '[') value_depth += 1;
            if (v == '}' || v == ']') {
              if (value_depth == 0) break;
              value_depth -= 1;
              cursor += 1;
              if (value_depth == 0) break;
              continue;
            }
            if (v == ',' && value_depth == 0) break;
            cursor += 1;
          }
          out = json.substr(start, cursor - start);
          return true;
        }
      }
      in_string = true;
      index += 1;
      continue;
    }
    if (c == '{' || c == '[') depth += 1;
    if (c == '}' || c == ']') depth -= 1;
    index += 1;
  }
  return false;
}

// The unescaped contents of a JSON string token, or `false` if the token is
// not a string. `\u` is refused rather than half-decoded: no expected value
// in the vector file needs it, and a wrong answer here would look like a
// library bug.
bool json_string(const std::string &token, std::string &out, std::string &error) {
  if (token.size() < 2 || token.front() != '"' || token.back() != '"') return false;
  out.clear();
  for (size_t i = 1; i + 1 < token.size(); i += 1) {
    char c = token[i];
    if (c != '\\') {
      out.push_back(c);
      continue;
    }
    i += 1;
    if (i + 1 > token.size()) return false;
    switch (token[i]) {
      case '"': out.push_back('"'); break;
      case '\\': out.push_back('\\'); break;
      case '/': out.push_back('/'); break;
      case 'b': out.push_back('\b'); break;
      case 'f': out.push_back('\f'); break;
      case 'n': out.push_back('\n'); break;
      case 'r': out.push_back('\r'); break;
      case 't': out.push_back('\t'); break;
      case 'u':
        error = "harness limit: this reader does not decode \\u escapes";
        return false;
      default: return false;
    }
  }
  return true;
}

// The number of elements in a top-level JSON array token.
bool array_length(const std::string &token, size_t &out) {
  if (token.size() < 2 || token.front() != '[' || token.back() != ']') return false;
  out = 0;
  int depth = 0;
  bool in_string = false;
  bool escaped = false;
  bool seen_value = false;
  for (size_t i = 1; i + 1 < token.size(); i += 1) {
    char c = token[i];
    if (in_string) {
      if (escaped) escaped = false;
      else if (c == '\\') escaped = true;
      else if (c == '"') in_string = false;
      continue;
    }
    if (c == '"') {
      in_string = true;
      seen_value = true;
      continue;
    }
    if (c == '{' || c == '[') { depth += 1; seen_value = true; continue; }
    if (c == '}' || c == ']') { depth -= 1; continue; }
    if (c == ',' && depth == 0) { out += 1; continue; }
    if (c != ' ' && c != '\t' && c != '\n' && c != '\r') seen_value = true;
  }
  if (seen_value) out += 1;
  return true;
}

// --- reason tokens -------------------------------------------------------

// Written out rather than derived, on purpose: this table and the header's
// enum are two independent statements of the same contract, and a mismatch
// between them is exactly the drift the ABI promises will not happen.
int reason_code(const std::string &token) {
  static const std::map<std::string, int> codes = {
      {"INVALID_JWS_FORMAT", APRV_REASON_INVALID_JWS_FORMAT},
      {"INVALID_CERTIFICATE", APRV_REASON_INVALID_CERTIFICATE},
      {"INVALID_CERTIFICATE_PURPOSE", APRV_REASON_INVALID_CERTIFICATE_PURPOSE},
      {"INVALID_CHAIN", APRV_REASON_INVALID_CHAIN},
      {"INVALID_SIGNATURE", APRV_REASON_INVALID_SIGNATURE},
      {"WRONG_BUNDLE_ID", APRV_REASON_WRONG_BUNDLE_ID},
      {"WRONG_ENVIRONMENT", APRV_REASON_WRONG_ENVIRONMENT},
      {"WRONG_APP_APPLE_ID", APRV_REASON_WRONG_APP_APPLE_ID},
      {"INVALID_RECEIPT_FORMAT", APRV_REASON_INVALID_RECEIPT_FORMAT},
      {"DEVICE_HASH_MISMATCH", APRV_REASON_DEVICE_HASH_MISMATCH},
      {"STALE_PAYLOAD", APRV_REASON_STALE_PAYLOAD},
  };
  auto found = codes.find(token);
  return found == codes.end() ? -1 : found->second;
}

bool decode_hex(const std::string &text, std::vector<unsigned char> &out) {
  if (text.size() % 2 != 0) return false;
  out.clear();
  for (size_t i = 0; i < text.size(); i += 2) {
    unsigned value = 0;
    for (size_t nibble = 0; nibble < 2; nibble += 1) {
      char c = text[i + nibble];
      unsigned digit;
      if (c >= '0' && c <= '9') digit = static_cast<unsigned>(c - '0');
      else if (c >= 'a' && c <= 'f') digit = static_cast<unsigned>(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F') digit = static_cast<unsigned>(c - 'A' + 10);
      else return false;
      value = value * 16 + digit;
    }
    out.push_back(static_cast<unsigned char>(value));
  }
  return true;
}

// --- anchors -------------------------------------------------------------

struct Anchors {
  std::vector<std::vector<unsigned char>> owned;
  std::vector<const uint8_t *> pointers;
  std::vector<size_t> lengths;

  bool load(const Case &kase, std::string &error) {
    for (const std::string &path : kase.all("root")) {
      std::vector<unsigned char> der;
      if (!read_file(path, der)) {
        error = "cannot read anchor " + path;
        return false;
      }
      owned.push_back(std::move(der));
    }
    for (const auto &der : owned) {
      pointers.push_back(der.data());
      lengths.push_back(der.size());
    }
    return true;
  }

  bool builtin() const { return owned.empty(); }
  const uint8_t *const *ders() const { return builtin() ? nullptr : pointers.data(); }
  const size_t *lens() const { return builtin() ? nullptr : lengths.data(); }
  size_t count() const { return owned.size(); }
};

// --- one case ------------------------------------------------------------

struct Outcome {
  int status = 0;
  std::string json;
};

bool run_case(const Case &kase, std::string &error, Outcome &outcome) {
  const std::string op = kase.get("op");

  Anchors anchors;
  if (kase.get("roots") == "files" && !anchors.load(kase, error)) return false;

  std::vector<unsigned char> input;
  if (!read_file(kase.get("input"), input)) {
    error = "cannot read input " + kase.get("input");
    return false;
  }
  // Every string the ABI takes is NUL-terminated; a fixture is a byte range.
  std::string input_text(input.begin(), input.end());

  AprvResult result = {0, nullptr};

  if (op == "verifyTransaction" || op == "verifyAppTransaction" || op == "verifyRaw") {
    AprvJwsVerifier *verifier =
        anchors.builtin()
            ? aprv_verifier_new_jws(kase.get("bundleId").c_str(),
                                    static_cast<uint32_t>(std::stoul(kase.get("envs"))),
                                    std::stoull(kase.get("appAppleId")),
                                    std::stoull(kase.get("maxSignedAgeSecs")))
            : aprv_verifier_new_jws_with_roots(
                  kase.get("bundleId").c_str(),
                  static_cast<uint32_t>(std::stoul(kase.get("envs"))),
                  std::stoull(kase.get("appAppleId")),
                  std::stoull(kase.get("maxSignedAgeSecs")), anchors.ders(), anchors.lens(),
                  anchors.count());
    if (verifier == nullptr) {
      error = "aprv_verifier_new_jws refused the configuration";
      return false;
    }
    if (op == "verifyTransaction") {
      aprv_verify_transaction(verifier, input_text.c_str(), &result);
    } else if (op == "verifyAppTransaction") {
      aprv_verify_app_transaction(verifier, input_text.c_str(), &result);
    } else {
      aprv_verify_raw(verifier, input_text.c_str(), &result);
    }
    aprv_verifier_free_jws(verifier);
  } else if (op == "verifyReceipt" || op == "verifyReceiptBase64") {
    AprvReceiptVerifier *verifier =
        anchors.builtin()
            ? aprv_verifier_new_receipt(kase.get("bundleId").c_str())
            : aprv_verifier_new_receipt_with_roots(kase.get("bundleId").c_str(), anchors.ders(),
                                                   anchors.lens(), anchors.count());
    if (verifier == nullptr) {
      error = "aprv_verifier_new_receipt refused the configuration";
      return false;
    }
    std::vector<unsigned char> guid;
    if (kase.has("deviceGuidHex") && !decode_hex(kase.get("deviceGuidHex"), guid)) {
      aprv_verifier_free_receipt(verifier);
      error = "deviceGuidHex is not hex";
      return false;
    }
    if (op == "verifyReceipt") {
      if (guid.empty()) {
        aprv_verify_receipt_der(verifier, input.data(), input.size(), &result);
      } else {
        aprv_verify_receipt_der_with_device_guid(verifier, input.data(), input.size(),
                                                 guid.data(), guid.size(), &result);
      }
    } else {
      if (guid.empty()) {
        aprv_verify_receipt_base64(verifier, input_text.c_str(), &result);
      } else {
        aprv_verify_receipt_base64_with_device_guid(verifier, input_text.c_str(), guid.data(),
                                                    guid.size(), &result);
      }
    }
    aprv_verifier_free_receipt(verifier);
  } else if (op == "verifyReceiptEndpoint") {
    uint32_t environment = static_cast<uint32_t>(std::stoul(kase.get("endpointEnv")));
    AprvReceiptEndpoint *endpoint =
        anchors.builtin() ? aprv_endpoint_new(environment)
                          : aprv_endpoint_new_with_roots(environment, anchors.ders(),
                                                         anchors.lens(), anchors.count());
    if (endpoint == nullptr) {
      error = "aprv_endpoint_new refused the configuration";
      return false;
    }
    std::vector<unsigned char> body;
    if (!read_file(kase.get("request"), body)) {
      aprv_endpoint_free(endpoint);
      error = "cannot read request " + kase.get("request");
      return false;
    }
    std::string body_text(body.begin(), body.end());
    char *response = nullptr;
    int status = aprv_verify_receipt_endpoint_json(endpoint, body_text.c_str(), &response);
    aprv_endpoint_free(endpoint);
    if (status != APRV_REASON_OK) {
      error = "the endpoint call itself failed with status " + std::to_string(status);
      return false;
    }
    // The endpoint never reports a verdict through the return value: the
    // Apple status code is a field of the body it answers.
    result.status = APRV_REASON_OK;
    result.json = response;
  } else {
    error = "no adapter for operation " + op;
    return false;
  }

  outcome.status = result.status;
  outcome.json = result.json == nullptr ? std::string() : std::string(result.json);
  aprv_string_free(result.json);
  return true;
}

bool check_expectations(const Case &kase, const Outcome &outcome, std::string &error) {
  const std::string expect = kase.get("expect");

  if (expect == "error") {
    const std::string token = kase.get("reason");
    int wanted = reason_code(token);
    if (wanted < 0) {
      error = "unknown expected reason " + token;
      return false;
    }
    if (outcome.status != wanted) {
      error = "reason: expected " + token + " (" + std::to_string(wanted) + "), got status " +
              std::to_string(outcome.status) + " " + outcome.json;
      return false;
    }
    // The status is the contract; the token in the body must agree with it.
    std::string token_value;
    std::string decoded;
    std::string reader_error;
    if (!top_level_value(outcome.json, "reason", token_value) ||
        !json_string(token_value, decoded, reader_error) || decoded != token) {
      error = "the error body does not name " + token + ": " + outcome.json;
      return false;
    }
    return true;
  }

  if (outcome.status != APRV_REASON_OK) {
    error = "expected success, got status " + std::to_string(outcome.status) + " " + outcome.json;
    return false;
  }

  for (const std::string &field : kase.all("field")) {
    size_t separator = field.find("~>");
    if (separator == std::string::npos || field.size() < separator + 4) {
      error = "unparseable manifest field " + field;
      return false;
    }
    const std::string path = field.substr(0, separator);
    const char tag = field[separator + 2];
    const std::string wanted = field.substr(separator + 4);

    const bool is_length = path.size() > 7 && path.compare(path.size() - 7, 7, ".length") == 0;
    const std::string key = is_length ? path.substr(0, path.size() - 7) : path;

    std::string token;
    const bool present = top_level_value(outcome.json, key, token);

    if (tag == 'z') {
      if (present && token != "null") {
        error = path + ": expected absent, got " + token;
        return false;
      }
      continue;
    }
    if (!present) {
      error = path + ": expected " + wanted + ", got nothing";
      return false;
    }
    if (is_length) {
      size_t length = 0;
      if (!array_length(token, length)) {
        error = path + ": " + key + " is not an array";
        return false;
      }
      if (std::to_string(length) != wanted) {
        error = path + ": expected " + wanted + ", got " + std::to_string(length);
        return false;
      }
      continue;
    }
    if (tag == 's') {
      std::string decoded;
      std::string reader_error;
      if (!json_string(token, decoded, reader_error)) {
        error = path + ": " + (reader_error.empty() ? "not a JSON string: " + token : reader_error);
        return false;
      }
      if (decoded != wanted) {
        error = path + ": expected \"" + wanted + "\", got \"" + decoded + "\"";
        return false;
      }
      continue;
    }
    if (tag == 'n') {
      if (token != wanted) {
        error = path + ": expected " + wanted + ", got " + token;
        return false;
      }
      continue;
    }
    error = "unknown manifest field tag in " + field;
    return false;
  }
  return true;
}

}  // namespace

int main(int argc, char **argv) {
  if (argc != 2) {
    std::cerr << "usage: " << argv[0] << " <manifest-dir>\n";
    return 2;
  }
  const std::string manifest = std::string(argv[1]) + "/cases.tsv";
  std::ifstream stream(manifest);
  if (!stream) {
    std::cerr << "cannot read " << manifest
              << " — run: node tools/gen-cases-manifest.mjs " << argv[1] << "\n";
    return 2;
  }

  std::cout << "apple-purchase-receipt-verifier " << aprv_version() << " — C ABI conformance\n";

  size_t passed = 0;
  size_t failed = 0;
  size_t unsupported = 0;
  size_t skipped_fields = 0;
  size_t checked_fields = 0;

  std::string line;
  while (std::getline(stream, line)) {
    if (line.empty()) continue;
    Case kase;
    for (const std::string &part : split(line, '\t')) {
      size_t equals = part.find('=');
      if (equals == std::string::npos) {
        std::cerr << "FAIL  <manifest>: unparseable entry " << part << "\n";
        failed += 1;
        continue;
      }
      kase.entries.emplace_back(part.substr(0, equals), part.substr(equals + 1));
    }
    const std::string id = kase.get("id");
    skipped_fields += static_cast<size_t>(std::stoul(kase.get("skippedFields", "0")));
    checked_fields += kase.all("field").size();

    if (kase.has("unsupported")) {
      const std::string why = kase.get("unsupported");
      if (why != "clock") {
        // A new reason a case cannot run is a finding, not a skip.
        std::cerr << "FAIL  " << id << ": unsupported for an unrecognised reason \"" << why
                  << "\"\n";
        failed += 1;
        continue;
      }
      unsupported += 1;
      continue;
    }

    std::string error;
    Outcome outcome;
    if (!run_case(kase, error, outcome) || !check_expectations(kase, outcome, error)) {
      std::cerr << "FAIL  " << id << ": " << error << "\n";
      failed += 1;
      continue;
    }
    passed += 1;
  }

  std::cout << passed << " passed, " << failed << " failed, " << unsupported
            << " not runnable through the C ABI (no clock argument)\n";
  std::cout << checked_fields << " expected fields checked here, " << skipped_fields
            << " nested paths left to rust/ffi/tests/conformance.py\n";
  if (passed + failed + unsupported == 0) {
    std::cerr << "the manifest held no cases\n";
    return 2;
  }
  return failed == 0 ? 0 : 1;
}
