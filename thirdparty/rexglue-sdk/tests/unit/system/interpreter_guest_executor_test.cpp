#include <catch2/catch_test_macros.hpp>

#include <array>
#include <bit>
#include <cstdint>
#include <cstring>

#include <rex/system/interpreter_guest_executor.h>
#include <rex/system/ppc_decoder.h>

namespace {

constexpr uint32_t DForm(uint32_t primary, uint32_t rt, uint32_t ra, uint16_t immediate) {
  return (primary << 26) | (rt << 21) | (ra << 16) | immediate;
}

void StoreInstruction(uint8_t* memory, uint32_t address, uint32_t instruction) {
  instruction = std::byteswap(instruction);
  std::memcpy(memory + address, &instruction, sizeof(instruction));
}

}  // namespace

TEST_CASE("Runtime PPC decoder extracts core D-form fields", "[system][interpreter]") {
  const auto decoded = rex::runtime::DecodePpcInstruction(DForm(14, 3, 4, 0xFFF0));
  REQUIRE(decoded.opcode == rex::runtime::PpcOpcode::kAddImmediate);
  REQUIRE(decoded.rt == 3);
  REQUIRE(decoded.ra == 4);
  REQUIRE(decoded.immediate == -16);
}

TEST_CASE("PPC interpreter executes integer and memory operations", "[system][interpreter]") {
  std::array<uint8_t, 512> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(16);

  StoreInstruction(memory.data(), 0, DForm(14, 3, 0, 0x100));
  StoreInstruction(memory.data(), 4, DForm(14, 4, 0, 42));
  StoreInstruction(memory.data(), 8, DForm(36, 4, 3, 0));
  StoreInstruction(memory.data(), 12, DForm(32, 5, 3, 0));
  StoreInstruction(memory.data(), 16, 0x4E800020);
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(result.instructions_executed == 5);
  REQUIRE(context.r5.u64 == 42);
  REQUIRE(memory[0x100] == 0);
  REQUIRE(memory[0x103] == 42);
}

TEST_CASE("PPC interpreter reports unsupported instructions precisely", "[system][interpreter]") {
  std::array<uint8_t, 16> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor;
  StoreInstruction(memory.data(), 0, 0xFFFFFFFF);

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.status == rex::runtime::GuestExecutionStatus::kFault);
  REQUIRE(result.guest_address == 0);
  REQUIRE(result.instruction == 0xFFFFFFFF);
  REQUIRE(result.instructions_executed == 1);
}

TEST_CASE("PPC interpreter follows relative branches", "[system][interpreter]") {
  std::array<uint8_t, 32> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(16);

  // b +8; skipped instruction; li r3, 9; blr.
  StoreInstruction(memory.data(), 0, (18u << 26) | 8u);
  StoreInstruction(memory.data(), 4, DForm(14, 3, 0, 1));
  StoreInstruction(memory.data(), 8, DForm(14, 3, 0, 9));
  StoreInstruction(memory.data(), 12, 0x4E800020);

  context.lr = 0xBCBCBCBC;
  const auto result = executor.Execute(context, memory.data(), 0);
  REQUIRE(result.succeeded());
  REQUIRE(context.r3.u64 == 9);
  REQUIRE(result.instructions_executed == 3);
}
