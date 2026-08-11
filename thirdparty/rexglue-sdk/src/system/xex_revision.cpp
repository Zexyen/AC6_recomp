#include <rex/system/xex_revision.h>

#include <algorithm>
#include <cctype>

#include <rex/crypto/sha256.h>

namespace rex::runtime {

bool IsValidSha256(std::string_view hash) {
  return hash.size() == 64 &&
         std::ranges::all_of(hash, [](unsigned char value) {
           return std::isxdigit(value) != 0;
         });
}

XexRevisionVerification VerifyXexRevision(
    std::span<const uint8_t> image, std::string_view expected_sha256) {
  if (!IsValidSha256(expected_sha256)) {
    return {X_STATUS_INVALID_PARAMETER, {}};
  }
  if (image.empty()) {
    return {X_STATUS_INVALID_PARAMETER, {}};
  }

  const auto contents = std::string_view(
      reinterpret_cast<const char*>(image.data()), image.size());
  auto actual = rex::crypto::sha256(contents);
  const bool matches = std::ranges::equal(
      actual, expected_sha256,
      [](unsigned char left, unsigned char right) {
        return std::tolower(left) == std::tolower(right);
      });
  return {matches ? X_STATUS_SUCCESS : X_STATUS_ACCESS_DENIED,
          std::move(actual)};
}

}  // namespace rex::runtime
