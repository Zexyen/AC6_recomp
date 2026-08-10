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

constexpr uint32_t DSForm(uint32_t primary, uint32_t rt, uint32_t ra,
                          int16_t displacement, uint32_t xo = 0) {
  return (primary << 26) | (rt << 21) | (ra << 16) |
         (static_cast<uint16_t>(displacement) & 0xFFFC) | xo;
}

constexpr uint32_t MForm(uint32_t primary, uint32_t rs, uint32_t ra,
                         uint32_t sh_rb, uint32_t mb, uint32_t me,
                         bool record = false) {
  return (primary << 26) | (rs << 21) | (ra << 16) | (sh_rb << 11) |
         (mb << 6) | (me << 1) | static_cast<uint32_t>(record);
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

TEST_CASE("PPC interpreter handles byte halfword and update-form memory operations",
          "[system][interpreter]") {
  std::array<uint8_t, 512> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(16);

  // li r3, 0x100; li r4, -128; stbu r4, 1(r3); lbz r5, 0(r3);
  // sthu r4, 2(r3); lha r6, 0(r3); blr
  StoreInstruction(memory.data(), 0, DForm(14, 3, 0, 0x100));
  StoreInstruction(memory.data(), 4, DForm(14, 4, 0, 0xFF80));
  StoreInstruction(memory.data(), 8, DForm(39, 4, 3, 1));
  StoreInstruction(memory.data(), 12, DForm(34, 5, 3, 0));
  StoreInstruction(memory.data(), 16, DForm(45, 4, 3, 2));
  StoreInstruction(memory.data(), 20, DForm(42, 6, 3, 0));
  StoreInstruction(memory.data(), 24, 0x4E800020);
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r3.u64 == 0x103);
  REQUIRE(context.r5.u64 == 0x80);
  REQUIRE(context.r6.s64 == -128);
  REQUIRE(memory[0x101] == 0x80);
  REQUIRE(memory[0x103] == 0xFF);
  REQUIRE(memory[0x104] == 0x80);
}

TEST_CASE("PPC interpreter handles indexed memory addressing", "[system][interpreter]") {
  std::array<uint8_t, 512> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(16);

  StoreInstruction(memory.data(), 0, DForm(14, 3, 0, 0x100));
  StoreInstruction(memory.data(), 4, DForm(14, 4, 0, 4));
  StoreInstruction(memory.data(), 8, DForm(14, 5, 0, 0x1234));
  StoreInstruction(memory.data(), 12, XForm(5, 3, 4, 407));
  StoreInstruction(memory.data(), 16, XForm(6, 3, 4, 279));
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r6.u64 == 0x1234);
  REQUIRE(memory[0x104] == 0x12);
  REQUIRE(memory[0x105] == 0x34);
}

TEST_CASE("PPC interpreter executes register arithmetic and record forms",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(16);

  StoreInstruction(memory.data(), 0, DForm(14, 3, 0, 9));
  StoreInstruction(memory.data(), 4, DForm(14, 4, 0, 4));
  StoreInstruction(memory.data(), 8, XForm(5, 3, 4, 266));
  StoreInstruction(memory.data(), 12, XForm(6, 4, 3, 40));
  StoreInstruction(memory.data(), 16, XForm(7, 6, 0, 104) | 1u);
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r5.u64 == 13);
  REQUIRE(context.r6.u64 == 5);
  REQUIRE(context.r7.s64 == -5);
  REQUIRE(context.cr0.lt == 1);
}

TEST_CASE("Runtime PPC decoder extracts DS-form and rotate-mask fields",
          "[system][interpreter]") {
  const auto load = rex::runtime::DecodePpcInstruction(DSForm(58, 3, 1, -16, 1));
  REQUIRE(load.opcode == rex::runtime::PpcOpcode::kLoadDoublewordUpdate);
  REQUIRE(load.rt == 3);
  REQUIRE(load.ra == 1);
  REQUIRE(load.immediate == -16);

  const auto rotate = rex::runtime::DecodePpcInstruction(MForm(21, 4, 5, 7, 8, 23, true));
  REQUIRE(rotate.opcode == rex::runtime::PpcOpcode::kRotateLeftWordImmediateAndMask);
  REQUIRE(rotate.shift == 7);
  REQUIRE(rotate.mask_begin == 8);
  REQUIRE(rotate.mask_end == 23);
  REQUIRE(rotate.record);
}

TEST_CASE("PPC interpreter handles doubleword stack and indexed memory operations",
          "[system][interpreter]") {
  std::array<uint8_t, 512> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(7);

  // stdu r1,-16(r1); std r3,8(r1); ld r4,8(r1); stdx r3,r1,r5; ldx r6,r1,r5
  StoreInstruction(memory.data(), 0, DSForm(62, 1, 1, -16, 1));
  StoreInstruction(memory.data(), 4, DSForm(62, 3, 1, 8));
  StoreInstruction(memory.data(), 8, DSForm(58, 4, 1, 8));
  StoreInstruction(memory.data(), 12, XForm(3, 1, 5, 149));
  StoreInstruction(memory.data(), 16, XForm(6, 1, 5, 21));
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.r1.u64 = 0x120;
  context.r3.u64 = 0x0123456789ABCDEF;
  context.r5.u64 = 0x18;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r1.u64 == 0x110);
  REQUIRE(context.r4.u64 == 0x0123456789ABCDEF);
  REQUIRE(context.r6.u64 == 0x0123456789ABCDEF);
  REQUIRE(memory[0x110] == 0x00);
  REQUIRE(memory[0x117] == 0x20);
  REQUIRE(memory[0x118] == 0x01);
  REQUIRE(memory[0x11F] == 0xEF);
}

TEST_CASE("PPC interpreter executes word rotate mask and logical shifts",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(5);

  // rlwinm r5,r3,8,8,15; rlwnm r6,r3,r4,0,31; slw. r7,r8,r4; srw r9,r3,r10
  StoreInstruction(memory.data(), 0, MForm(21, 3, 5, 8, 8, 15));
  StoreInstruction(memory.data(), 4, MForm(23, 3, 6, 4, 0, 31));
  StoreInstruction(memory.data(), 8, XForm(8, 7, 4, 24) | 1u);
  StoreInstruction(memory.data(), 12, XForm(3, 9, 10, 536));
  StoreInstruction(memory.data(), 16, XForm(3, 11, 10, 24));
  context.r3.u64 = 0x12345678;
  context.r4.u64 = 4;
  context.r8.u64 = 0x08000000;
  context.r10.u64 = 32;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.status == rex::runtime::GuestExecutionStatus::kStopped);
  REQUIRE(context.r5.u64 == 0x00560000);
  REQUIRE(context.r6.u64 == 0x23456781);
  REQUIRE(context.r7.u64 == 0x80000000);
  REQUIRE(context.cr0.lt == 1);
  REQUIRE(context.r9.u64 == 0);
  REQUIRE(context.r11.u64 == 0);
}

TEST_CASE("Runtime PPC decoder recognizes scalar integer operations",
          "[system][interpreter]") {
  REQUIRE(rex::runtime::DecodePpcInstruction(DForm(7, 3, 4, 0xFFF9)).opcode ==
          rex::runtime::PpcOpcode::kMultiplyLowImmediate);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 0, 954)).opcode ==
          rex::runtime::PpcOpcode::kSignExtendByte);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 0, 26)).opcode ==
          rex::runtime::PpcOpcode::kCountLeadingZerosWord);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 5, 491)).opcode ==
          rex::runtime::PpcOpcode::kDivideWord);
}

TEST_CASE("PPC interpreter handles sign extension and leading-zero counts",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(7);

  StoreInstruction(memory.data(), 0, XForm(3, 4, 0, 954));
  StoreInstruction(memory.data(), 4, XForm(3, 5, 0, 922));
  StoreInstruction(memory.data(), 8, XForm(3, 6, 0, 986) | 1u);
  StoreInstruction(memory.data(), 12, XForm(7, 8, 0, 26));
  StoreInstruction(memory.data(), 16, XForm(9, 10, 0, 58));
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.r3.u64 = 0xFFFFFFFFFFFFFF80;
  context.r7.u64 = 0x0000F000;
  context.r9.u64 = 0x0000000100000000;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r4.s64 == -128);
  REQUIRE(context.r5.s64 == -128);
  REQUIRE(context.r6.s64 == -128);
  REQUIRE(context.cr0.lt == 1);
  REQUIRE(context.r8.u64 == 16);
  REQUIRE(context.r10.u64 == 31);
}

TEST_CASE("PPC interpreter executes scalar multiply and divide operations",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(10);

  StoreInstruction(memory.data(), 0, DForm(7, 4, 3, 0xFFFD));
  StoreInstruction(memory.data(), 4, XForm(5, 3, 12, 235));
  StoreInstruction(memory.data(), 8, XForm(6, 3, 12, 233));
  StoreInstruction(memory.data(), 12, XForm(7, 3, 12, 491));
  StoreInstruction(memory.data(), 16, XForm(8, 3, 12, 459));
  StoreInstruction(memory.data(), 20, XForm(9, 3, 12, 489));
  StoreInstruction(memory.data(), 24, XForm(10, 3, 12, 457));
  StoreInstruction(memory.data(), 28, XForm(11, 3, 13, 457) | 1u);
  StoreInstruction(memory.data(), 32, 0x4E800020);
  context.r3.u64 = 21;
  context.r4.u64 = 3;
  context.r12.u64 = 3;
  context.r13.u64 = 0;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r4.s64 == -63);
  REQUIRE(context.r5.s64 == 63);
  REQUIRE(context.r6.u64 == 63);
  REQUIRE(context.r7.s64 == 7);
  REQUIRE(context.r8.u64 == 7);
  REQUIRE(context.r9.s64 == 7);
  REQUIRE(context.r10.u64 == 7);
  REQUIRE(context.r11.u64 == 0);
  REQUIRE(context.cr0.eq == 1);
}
