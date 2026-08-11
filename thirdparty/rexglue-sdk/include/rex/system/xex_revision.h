#pragma once

#include <span>
#include <string>
#include <string_view>

#include <rex/system/xtypes.h>

namespace rex::runtime {

struct XexRevisionVerification {
  X_STATUS status = X_STATUS_UNSUCCESSFUL;
  std::string actual_sha256;

  bool succeeded() const { return status == X_STATUS_SUCCESS; }
};

bool IsValidSha256(std::string_view hash);
XexRevisionVerification VerifyXexRevision(
    std::span<const uint8_t> image, std::string_view expected_sha256);

}  // namespace rex::runtime
