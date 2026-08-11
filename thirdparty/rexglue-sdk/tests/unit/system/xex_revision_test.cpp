#include <catch2/catch_test_macros.hpp>

#include <array>

#include <rex/system/xex_revision.h>

using rex::X_STATUS;

TEST_CASE("XEX revision verification requires a valid expected SHA-256",
          "[system][xex]") {
  const std::array<uint8_t, 4> image{'X', 'E', 'X', '2'};

  REQUIRE_FALSE(rex::runtime::IsValidSha256(""));
  REQUIRE_FALSE(rex::runtime::IsValidSha256(std::string(64, 'z')));
  REQUIRE(rex::runtime::VerifyXexRevision(image, "bad").status ==
          X_STATUS_INVALID_PARAMETER);
}

TEST_CASE("XEX revision verification accepts only matching image contents",
          "[system][xex]") {
  const std::array<uint8_t, 4> image{'X', 'E', 'X', '2'};
  constexpr std::string_view expected =
      "8550dba88229fe0f2dc4ea0f8e1433d0993fbe7ef030302c0ed2219106848917";

  const auto accepted = rex::runtime::VerifyXexRevision(image, expected);
  REQUIRE(accepted.succeeded());
  REQUIRE(accepted.actual_sha256 == expected);

  const auto rejected = rex::runtime::VerifyXexRevision(
      image, std::string(64, '0'));
  REQUIRE(rejected.status == X_STATUS_ACCESS_DENIED);
  REQUIRE(rejected.actual_sha256 == expected);
}
