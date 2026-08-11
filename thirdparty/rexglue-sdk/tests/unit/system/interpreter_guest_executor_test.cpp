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

constexpr uint32_t CompareForm(bool logical, uint32_t cr_field, bool is_64_bit,
                               uint32_t ra, uint32_t rb) {
  return (31u << 26) | (cr_field << 23) |
         (static_cast<uint32_t>(is_64_bit) << 21) | (ra << 16) | (rb << 11) |
         (static_cast<uint32_t>(logical ? 32 : 0) << 1);
}

constexpr uint32_t XLForm(uint32_t bo, uint32_t bi, uint32_t xo,
                          bool link = false) {
  return (19u << 26) | (bo << 21) | (bi << 16) | (xo << 1) |
         static_cast<uint32_t>(link);
}

constexpr uint32_t CrForm(uint32_t target, uint32_t source_a,
                          uint32_t source_b, uint32_t xo) {
  return (19u << 26) | (target << 21) | (source_a << 16) |
         (source_b << 11) | (xo << 1);
}

constexpr uint32_t FloatXForm(uint32_t primary, uint32_t ft, uint32_t fa,
                              uint32_t fb, uint32_t xo) {
  return (primary << 26) | (ft << 21) | (fa << 16) | (fb << 11) | (xo << 1);
}

constexpr uint32_t FloatAForm(uint32_t primary, uint32_t ft, uint32_t fa,
                              uint32_t fb, uint32_t fc, uint32_t xo) {
  return (primary << 26) | (ft << 21) | (fa << 16) | (fb << 11) |
         (fc << 6) | (xo << 1);
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

TEST_CASE("Runtime PPC decoder recognizes register compares CR logic and bcctr",
          "[system][interpreter]") {
  const auto compare = rex::runtime::DecodePpcInstruction(CompareForm(false, 3, true, 4, 5));
  REQUIRE(compare.opcode == rex::runtime::PpcOpcode::kCompare);
  REQUIRE(compare.cr_field == 3);
  REQUIRE(compare.is_64_bit);
  REQUIRE(compare.ra == 4);
  REQUIRE(compare.rb == 5);

  const auto cr_xor = rex::runtime::DecodePpcInstruction(CrForm(2, 8, 13, 193));
  REQUIRE(cr_xor.opcode == rex::runtime::PpcOpcode::kCrXor);
  REQUIRE(cr_xor.rt == 2);
  REQUIRE(cr_xor.ra == 8);
  REQUIRE(cr_xor.rb == 13);

  const auto bcctr = rex::runtime::DecodePpcInstruction(XLForm(12, 2, 528, true));
  REQUIRE(bcctr.opcode == rex::runtime::PpcOpcode::kBranchConditionalToCountRegister);
  REQUIRE(bcctr.bo == 12);
  REQUIRE(bcctr.bi == 2);
  REQUIRE(bcctr.link);
}

TEST_CASE("PPC interpreter compares registers and applies CR logical operations",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(5);

  // cmpw cr2,r3,r4; cmplw cr3,r3,r4; crand cr0.eq,cr2.lt,cr3.gt; blr
  StoreInstruction(memory.data(), 0, CompareForm(false, 2, false, 3, 4));
  StoreInstruction(memory.data(), 4, CompareForm(true, 3, false, 3, 4));
  StoreInstruction(memory.data(), 8, CrForm(2, 8, 13, 257));
  StoreInstruction(memory.data(), 12, 0x4E800020);
  context.r3.u64 = 0xFFFFFFFF;
  context.r4.u64 = 1;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.cr2.lt == 1);
  REQUIRE(context.cr3.gt == 1);
  REQUIRE(context.cr0.eq == 1);
}

TEST_CASE("PPC interpreter branches conditionally through the count register",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(7);

  // li r3,20; mtctr r3; cmpw cr0,r4,r5; beqctr; skipped; li r6,2; blr
  StoreInstruction(memory.data(), 0, DForm(14, 3, 0, 20));
  StoreInstruction(memory.data(), 4, SprForm(3, 9, 467));
  StoreInstruction(memory.data(), 8, CompareForm(false, 0, false, 4, 5));
  StoreInstruction(memory.data(), 12, XLForm(12, 2, 528));
  StoreInstruction(memory.data(), 16, DForm(14, 6, 0, 1));
  StoreInstruction(memory.data(), 20, DForm(14, 6, 0, 2));
  StoreInstruction(memory.data(), 24, 0x4E800020);
  context.r4.u64 = 9;
  context.r5.u64 = 9;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r6.u64 == 2);
  REQUIRE(context.ctr.u64 == 20);
}

TEST_CASE("Runtime PPC decoder recognizes complemented logical and arithmetic shifts",
          "[system][interpreter]") {
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 5, 60)).opcode ==
          rex::runtime::PpcOpcode::kAndComplement);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 5, 284)).opcode ==
          rex::runtime::PpcOpcode::kEquivalent);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 5, 792)).opcode ==
          rex::runtime::PpcOpcode::kShiftRightArithmeticWord);
  const auto immediate = rex::runtime::DecodePpcInstruction(XForm(3, 4, 7, 824) | 1u);
  REQUIRE(immediate.opcode == rex::runtime::PpcOpcode::kShiftRightArithmeticWordImmediate);
  REQUIRE(immediate.shift == 7);
  REQUIRE(immediate.record);
}

TEST_CASE("PPC interpreter executes complemented logical operations",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(7);

  StoreInstruction(memory.data(), 0, XForm(3, 5, 4, 60));
  StoreInstruction(memory.data(), 4, XForm(3, 6, 4, 412));
  StoreInstruction(memory.data(), 8, XForm(3, 7, 4, 476));
  StoreInstruction(memory.data(), 12, XForm(3, 8, 4, 124));
  StoreInstruction(memory.data(), 16, XForm(3, 9, 4, 284) | 1u);
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.r3.u64 = 0x0F0F;
  context.r4.u64 = 0x00FF;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r5.u64 == 0x0F00);
  REQUIRE(context.r6.u64 == 0xFFFFFFFFFFFFFF0F);
  REQUIRE(context.r7.u64 == 0xFFFFFFFFFFFFFFF0);
  REQUIRE(context.r8.u64 == 0xFFFFFFFFFFFFF000);
  REQUIRE(context.r9.u64 == 0xFFFFFFFFFFFFF00F);
  REQUIRE(context.cr0.lt == 1);
}

TEST_CASE("PPC interpreter executes arithmetic word shifts and updates carry",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(5);

  // srawi r5,r3,2; sraw. r6,r3,r4; srawi. r7,r8,0; blr
  StoreInstruction(memory.data(), 0, XForm(3, 5, 2, 824));
  StoreInstruction(memory.data(), 4, XForm(3, 6, 4, 792) | 1u);
  StoreInstruction(memory.data(), 8, XForm(8, 7, 0, 824) | 1u);
  StoreInstruction(memory.data(), 12, 0x4E800020);
  context.r3.s64 = -7;
  context.r4.u64 = 40;
  context.r8.s64 = -8;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r5.s64 == -2);
  REQUIRE(context.r6.s64 == -1);
  REQUIRE(context.r7.s64 == -8);
  REQUIRE(context.xer.ca == 0);
  REQUIRE(context.cr0.lt == 1);
}

TEST_CASE("Runtime PPC decoder recognizes carry-aware arithmetic",
          "[system][interpreter]") {
  const auto addic = rex::runtime::DecodePpcInstruction(DForm(13, 3, 4, 1));
  REQUIRE(addic.opcode == rex::runtime::PpcOpcode::kAddImmediateCarrying);
  REQUIRE(addic.record);
  REQUIRE(rex::runtime::DecodePpcInstruction(DForm(8, 3, 4, 1)).opcode ==
          rex::runtime::PpcOpcode::kSubtractFromImmediateCarrying);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 5, 10)).opcode ==
          rex::runtime::PpcOpcode::kAddCarrying);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 5, 136)).opcode ==
          rex::runtime::PpcOpcode::kSubtractFromExtended);
}

TEST_CASE("PPC interpreter propagates carry through extended addition",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(6);

  // addc r5,r3,r4; adde r6,r7,r8; addze r9,r10; addme. r11,r12; blr
  StoreInstruction(memory.data(), 0, XForm(5, 3, 4, 10));
  StoreInstruction(memory.data(), 4, XForm(6, 7, 8, 138));
  StoreInstruction(memory.data(), 8, XForm(9, 10, 0, 202));
  StoreInstruction(memory.data(), 12, XForm(11, 12, 0, 234) | 1u);
  StoreInstruction(memory.data(), 16, 0x4E800020);
  context.r3.u64 = UINT64_MAX;
  context.r4.u64 = 1;
  context.r7.u64 = UINT64_MAX;
  context.r8.u64 = 0;
  context.r10.u64 = UINT64_MAX;
  context.r12.u64 = 1;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r5.u64 == 0);
  REQUIRE(context.r6.u64 == 0);
  REQUIRE(context.r9.u64 == 0);
  REQUIRE(context.r11.u64 == 1);
  REQUIRE(context.xer.ca == 1);
  REQUIRE(context.cr0.gt == 1);
}

TEST_CASE("PPC interpreter executes carrying immediate and subtraction forms",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(7);

  StoreInstruction(memory.data(), 0, DForm(13, 4, 3, 1));
  StoreInstruction(memory.data(), 4, DForm(8, 5, 6, 10));
  StoreInstruction(memory.data(), 8, XForm(9, 7, 8, 8));
  StoreInstruction(memory.data(), 12, XForm(12, 10, 11, 136));
  StoreInstruction(memory.data(), 16, XForm(14, 13, 0, 200) | 1u);
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.r3.u64 = UINT64_MAX;
  context.r6.u64 = 3;
  context.r7.u64 = 7;
  context.r8.u64 = 9;
  context.r10.u64 = 5;
  context.r11.u64 = 8;
  context.r13.u64 = 0;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r4.u64 == 0);
  REQUIRE(context.r5.u64 == 7);
  REQUIRE(context.r9.u64 == 2);
  REQUIRE(context.r12.u64 == 3);
  REQUIRE(context.r14.u64 == 0);
  REQUIRE(context.xer.ca == 1);
  REQUIRE(context.cr0.eq == 1);
}

TEST_CASE("Runtime PPC decoder recognizes shifted immediates and doubleword shifts",
          "[system][interpreter]") {
  REQUIRE(rex::runtime::DecodePpcInstruction(DForm(25, 3, 4, 0x1234)).opcode ==
          rex::runtime::PpcOpcode::kOrImmediateShifted);
  REQUIRE(rex::runtime::DecodePpcInstruction(DForm(27, 3, 4, 0x1234)).immediate ==
          static_cast<int32_t>(0x12340000));
  const auto and_shifted = rex::runtime::DecodePpcInstruction(DForm(29, 3, 4, 0xFFFF));
  REQUIRE(and_shifted.opcode == rex::runtime::PpcOpcode::kAndImmediateShifted);
  REQUIRE(and_shifted.record);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 5, 27)).opcode ==
          rex::runtime::PpcOpcode::kShiftLeftDoubleword);
  REQUIRE(rex::runtime::DecodePpcInstruction(XForm(3, 4, 5, 539)).opcode ==
          rex::runtime::PpcOpcode::kShiftRightDoubleword);
}

TEST_CASE("PPC interpreter executes immediate logical variants",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(8);

  StoreInstruction(memory.data(), 0, DForm(25, 3, 4, 0x1234));
  StoreInstruction(memory.data(), 4, DForm(27, 4, 5, 0x00FF));
  StoreInstruction(memory.data(), 8, DForm(28, 3, 6, 0x00FF));
  StoreInstruction(memory.data(), 12, DForm(29, 3, 7, 0xFFFF));
  StoreInstruction(memory.data(), 16, DForm(24, 3, 8, 0x000F));
  StoreInstruction(memory.data(), 20, DForm(26, 8, 9, 0x00FF));
  StoreInstruction(memory.data(), 24, 0x4E800020);
  context.r3.u64 = 0xABCDEF01;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r4.u64 == 0xBBFDEF01);
  REQUIRE(context.r5.u64 == 0xBB02EF01);
  REQUIRE(context.r6.u64 == 1);
  REQUIRE(context.r7.u64 == 0xABCD0000);
  REQUIRE(context.r8.u64 == 0xABCDEF0F);
  REQUIRE(context.r9.u64 == 0xABCDEFF0);
  REQUIRE(context.cr0.lt == 0);
  REQUIRE(context.cr0.gt == 1);
}

TEST_CASE("PPC interpreter executes doubleword logical shifts",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(6);

  StoreInstruction(memory.data(), 0, XForm(3, 5, 4, 27));
  StoreInstruction(memory.data(), 4, XForm(3, 6, 7, 539) | 1u);
  StoreInstruction(memory.data(), 8, XForm(3, 8, 9, 27));
  StoreInstruction(memory.data(), 12, XForm(3, 10, 9, 539) | 1u);
  StoreInstruction(memory.data(), 16, 0x4E800020);
  context.r3.u64 = 0x8000000000000001;
  context.r4.u64 = 4;
  context.r7.u64 = 4;
  context.r9.u64 = 64;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r5.u64 == 0x10);
  REQUIRE(context.r6.u64 == 0x0800000000000000);
  REQUIRE(context.r8.u64 == 0);
  REQUIRE(context.r10.u64 == 0);
  REQUIRE(context.cr0.eq == 1);
}

TEST_CASE("PPC interpreter executes multiply-high and rotate-mask insert operations",
          "[system][interpreter]") {
  std::array<uint8_t, 64> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(7);

  StoreInstruction(memory.data(), 0, XForm(5, 3, 4, 75));
  StoreInstruction(memory.data(), 4, XForm(6, 3, 4, 11));
  StoreInstruction(memory.data(), 8, XForm(7, 8, 9, 73));
  StoreInstruction(memory.data(), 12, XForm(10, 8, 9, 9));
  StoreInstruction(memory.data(), 16, MForm(20, 11, 12, 8, 8, 15, true));
  StoreInstruction(memory.data(), 20, 0x4E800020);
  context.r3.u64 = 0xFFFFFFFF;
  context.r4.u64 = 2;
  context.r8.u64 = UINT64_MAX;
  context.r9.u64 = 2;
  context.r11.u64 = 0x12345678;
  context.r12.u64 = 0xAABBCCDD;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r5.s64 == -1);
  REQUIRE(context.r6.u64 == 1);
  REQUIRE(context.r7.s64 == -1);
  REQUIRE(context.r10.u64 == 1);
  REQUIRE(context.r12.u64 == 0xAA56CCDD);
  REQUIRE(context.cr0.lt == 1);
}

TEST_CASE("PPC interpreter executes indexed update memory variants",
          "[system][interpreter]") {
  std::array<uint8_t, 512> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(8);

  StoreInstruction(memory.data(), 0, XForm(3, 1, 2, 183));
  StoreInstruction(memory.data(), 4, XForm(4, 5, 6, 55));
  StoreInstruction(memory.data(), 8, XForm(7, 8, 9, 247));
  StoreInstruction(memory.data(), 12, XForm(10, 11, 12, 119));
  StoreInstruction(memory.data(), 16, XForm(13, 14, 15, 181));
  StoreInstruction(memory.data(), 20, XForm(16, 17, 18, 53));
  StoreInstruction(memory.data(), 24, 0x4E800020);
  context.r1.u64 = 0x100; context.r2.u64 = 4; context.r3.u64 = 0x89ABCDEF;
  context.r5.u64 = 0x100; context.r6.u64 = 4;
  context.r8.u64 = 0x110; context.r9.u64 = 1; context.r7.u64 = 0x7A;
  context.r11.u64 = 0x110; context.r12.u64 = 1;
  context.r14.u64 = 0x120; context.r15.u64 = 8; context.r13.u64 = 0x0123456789ABCDEF;
  context.r17.u64 = 0x120; context.r18.u64 = 8;
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.r1.u64 == 0x104);
  REQUIRE(context.r4.u64 == 0x89ABCDEF);
  REQUIRE(context.r5.u64 == 0x104);
  REQUIRE(context.r10.u64 == 0x7A);
  REQUIRE(context.r11.u64 == 0x111);
  REQUIRE(context.r14.u64 == 0x128);
  REQUIRE(context.r16.u64 == 0x0123456789ABCDEF);
  REQUIRE(context.r17.u64 == 0x128);
}

TEST_CASE("PPC interpreter reports bounded instruction and data memory faults",
          "[system][interpreter]") {
  std::array<uint8_t, 32> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(8, memory.size());

  auto fetch_fault = executor.Execute(context, memory.data(), 32);
  REQUIRE(fetch_fault.status == rex::runtime::GuestExecutionStatus::kFault);
  REQUIRE(fetch_fault.guest_address == 32);
  REQUIRE(fetch_fault.instructions_executed == 0);

  StoreInstruction(memory.data(), 0, DForm(32, 3, 0, 30));
  auto data_fault = executor.Execute(context, memory.data(), 0);
  REQUIRE(data_fault.status == rex::runtime::GuestExecutionStatus::kFault);
  REQUIRE(data_fault.guest_address == 0);
  REQUIRE(data_fault.instruction == DForm(32, 3, 0, 30));
  REQUIRE(data_fault.instructions_executed == 1);

  auto null_fault = executor.Execute(context, nullptr, 0);
  REQUIRE(null_fault.status == rex::runtime::GuestExecutionStatus::kFault);
  REQUIRE(null_fault.instructions_executed == 0);
}

TEST_CASE("Runtime PPC decoder recognizes baseline floating-point operations",
          "[system][interpreter]") {
  REQUIRE(rex::runtime::DecodePpcInstruction(DForm(50, 3, 4, 8)).opcode ==
          rex::runtime::PpcOpcode::kLoadFloatDouble);
  REQUIRE(rex::runtime::DecodePpcInstruction(DForm(52, 3, 4, 8)).opcode ==
          rex::runtime::PpcOpcode::kStoreFloatSingle);
  REQUIRE(rex::runtime::DecodePpcInstruction(FloatXForm(63, 3, 4, 5, 21)).opcode ==
          rex::runtime::PpcOpcode::kFloatAdd);
  REQUIRE(rex::runtime::DecodePpcInstruction(FloatXForm(63, 3, 0, 5, 264)).opcode ==
          rex::runtime::PpcOpcode::kFloatAbsolute);
}

TEST_CASE("PPC interpreter loads computes compares and stores floating-point values",
          "[system][interpreter]") {
  std::array<uint8_t, 256> memory{};
  PPCContext context{};
  rex::runtime::InterpreterGuestExecutor executor(9, memory.size());

  StoreInstruction(memory.data(), 0, DForm(50, 1, 3, 0));
  StoreInstruction(memory.data(), 4, DForm(48, 2, 3, 8));
  StoreInstruction(memory.data(), 8, FloatXForm(63, 4, 1, 2, 21));
  StoreInstruction(memory.data(), 12, FloatAForm(63, 5, 1, 0, 2, 25));
  StoreInstruction(memory.data(), 16, FloatXForm(63, 6, 0, 5, 40));
  StoreInstruction(memory.data(), 20, FloatXForm(63, 2 << 2, 4, 5, 0));
  StoreInstruction(memory.data(), 24, DForm(54, 4, 3, 16));
  StoreInstruction(memory.data(), 28, 0x4E800020);
  context.r3.u64 = 0x80;
  uint64_t double_bits = std::byteswap(std::bit_cast<uint64_t>(1.5));
  std::memcpy(memory.data() + 0x80, &double_bits, sizeof(double_bits));
  uint32_t float_bits = std::byteswap(std::bit_cast<uint32_t>(2.0f));
  std::memcpy(memory.data() + 0x88, &float_bits, sizeof(float_bits));
  context.lr = 0xBCBCBCBC;

  const auto result = executor.Execute(context, memory.data(), 0);

  REQUIRE(result.succeeded());
  REQUIRE(context.f1.f64 == 1.5);
  REQUIRE(context.f2.f64 == 2.0);
  REQUIRE(context.f4.f64 == 3.5);
  REQUIRE(context.f5.f64 == 3.0);
  REQUIRE(context.f6.f64 == -3.0);
  REQUIRE(context.cr2.gt == 1);
  uint64_t stored_bits;
  std::memcpy(&stored_bits, memory.data() + 0x90, sizeof(stored_bits));
  REQUIRE(std::byteswap(stored_bits) == std::bit_cast<uint64_t>(3.5));
}
