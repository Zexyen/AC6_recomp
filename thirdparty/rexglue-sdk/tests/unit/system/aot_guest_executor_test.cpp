#include <catch2/catch_test_macros.hpp>

#include <array>

#include <rex/system/aot_guest_executor.h>

namespace {

void TestFunction(PPCContext& context, uint8_t* memory_base) {
  context.r3.u64 += 7;
  memory_base[3] = 0xAC;
}

}  // namespace

TEST_CASE("AOT guest executor dispatches registered functions", "[system][executor]") {
  rex::runtime::AotGuestExecutor executor;
  PPCContext context{};
  std::array<uint8_t, 16> memory{};
  constexpr uint32_t kGuestAddress = 0x82000000;

  context.r3.u64 = 5;
  executor.RegisterFunction(kGuestAddress, TestFunction);

  const auto result = executor.Execute(context, memory.data(), kGuestAddress);

  REQUIRE(result.succeeded());
  REQUIRE(result.guest_address == kGuestAddress);
  REQUIRE(context.r3.u64 == 12);
  REQUIRE(memory[3] == 0xAC);
  REQUIRE(executor.LookupFunction(kGuestAddress) == TestFunction);
}

TEST_CASE("AOT guest executor reports unmapped addresses", "[system][executor]") {
  rex::runtime::AotGuestExecutor executor;
  PPCContext context{};
  std::array<uint8_t, 16> memory{};
  constexpr uint32_t kGuestAddress = 0x82000000;

  const auto result = executor.Execute(context, memory.data(), kGuestAddress);

  REQUIRE_FALSE(result.succeeded());
  REQUIRE(result.status == rex::runtime::GuestExecutionStatus::kUnmappedAddress);
  REQUIRE(result.guest_address == kGuestAddress);
}

TEST_CASE("AOT guest executor unregisters null functions", "[system][executor]") {
  rex::runtime::AotGuestExecutor executor;
  constexpr uint32_t kGuestAddress = 0x82000000;

  executor.RegisterFunction(kGuestAddress, TestFunction);
  REQUIRE(executor.LookupFunction(kGuestAddress) == TestFunction);

  executor.RegisterFunction(kGuestAddress, nullptr);
  REQUIRE(executor.LookupFunction(kGuestAddress) == nullptr);
}
