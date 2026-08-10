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

constexpr uint32_t XForm(uint32_t rt, uint32_t ra, uint32_t rb, uint32_t xo) {
  return (31u << 26) | (rt << 21) | (ra << 16) | (rb << 11) | (xo << 1);
}

constexpr uint32_t SprForm(uint32_t rs_rt, uint32_t spr, uint32_t xo) {
  const uint32_t encoded_spr = ((spr & 31) << 5) | ((spr >> 5) & 31);
  return (31u << 26) | (rs_rt << 21) | (encoded_spr << 11) | (xo << 1);
}

constexpr uint32_t BForm(uint32_t bo, uint32_t bi, int16_t displacement) {
  return (16u << 26) | (bo << 21) | (bi << 16) |
         (static_cast<uint16_t>(displacement) & 0xFFFC);
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

TEST_CASE("PPC interpreter executes count-register loops", "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(32);

  // li r3, 0; li r4, 3; mtctr r4; addi r3, r3, 1; bdnz -4; blr
  StoreInstruction(memory.data(), 0, DForm(14, 3, 0, 0));
  StoreInstruction(memory.data(), 4, DForm(14, 4, 0, 3));
  StoreInstruction(memory.data(), 8, SprForm(4, 9, 467));
  StoreInstruction(memory.data(), 12, DForm(14, 3, 3, 1));
  StoreInstruction(memory.data(), 16, BForm(16, 0, -4));
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r3.u64 == 3);
  REQUIRE(context.ctr.u64 == 0);
}

TEST_CASE("PPC interpreter branches using condition-register results", "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(16);

  // li r3, 7; cmpwi cr0, r3, 7; beq +8; li r4, 1; li r4, 2; blr
  StoreInstruction(memory.data(), 0, DForm(14, 3, 0, 7));
  StoreInstruction(memory.data(), 4, (11u << 26) | (3u << 16) | 7u);
  StoreInstruction(memory.data(), 8, BForm(12, 2, 8));
  StoreInstruction(memory.data(), 12, DForm(14, 4, 0, 1));
  StoreInstruction(memory.data(), 16, DForm(14, 4, 0, 2));
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.cr0.eq == 1);
  REQUIRE(context.r4.u64 == 2);
}

TEST_CASE("PPC interpreter handles logical registers and link-register SPR moves",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(6);

  StoreInstruction(memory.data(), 0, DForm(14, 3, 0, 0x0F0F));
  StoreInstruction(memory.data(), 4, DForm(14, 4, 0, 0x00FF));
  StoreInstruction(memory.data(), 8, XForm(3, 5, 4, 444));
  StoreInstruction(memory.data(), 12, SprForm(5, 8, 467));
  StoreInstruction(memory.data(), 16, SprForm(6, 8, 339));
  StoreInstruction(memory.data(), 20, DForm(14, 7, 0, 0xBCBC));
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.status == rex::runtime::GuestExecutionStatus::kStopped);
  REQUIRE(context.r5.u64 == 0x0FFF);
  REQUIRE(context.r6.u64 == 0x0FFF);
  REQUIRE(context.lr == 0x0FFF);
}
