#include <bit>
#include <cstdint>
#include <cstring>

#include <rex/system/interpreter_guest_executor.h>
#include <rex/system/ppc_decoder.h>

namespace rex::runtime {
namespace {

PPCRegister& Gpr(PPCContext& context, uint8_t index) {
  switch (index) {
#define REX_GPR_CASE(n) case n: return context.r##n
    REX_GPR_CASE(0); REX_GPR_CASE(1); REX_GPR_CASE(2); REX_GPR_CASE(3);
    REX_GPR_CASE(4); REX_GPR_CASE(5); REX_GPR_CASE(6); REX_GPR_CASE(7);
    REX_GPR_CASE(8); REX_GPR_CASE(9); REX_GPR_CASE(10); REX_GPR_CASE(11);
    REX_GPR_CASE(12); REX_GPR_CASE(13); REX_GPR_CASE(14); REX_GPR_CASE(15);
    REX_GPR_CASE(16); REX_GPR_CASE(17); REX_GPR_CASE(18); REX_GPR_CASE(19);
    REX_GPR_CASE(20); REX_GPR_CASE(21); REX_GPR_CASE(22); REX_GPR_CASE(23);
    REX_GPR_CASE(24); REX_GPR_CASE(25); REX_GPR_CASE(26); REX_GPR_CASE(27);
    REX_GPR_CASE(28); REX_GPR_CASE(29); REX_GPR_CASE(30); REX_GPR_CASE(31);
#undef REX_GPR_CASE
    default: return context.r0;
  }
}

uint32_t LoadBe32(const uint8_t* address) {
  uint32_t value;
  std::memcpy(&value, address, sizeof(value));
  return std::byteswap(value);
}

void StoreBe32(uint8_t* address, uint32_t value) {
  value = std::byteswap(value);
  std::memcpy(address, &value, sizeof(value));
}

}  // namespace

GuestExecutionResult InterpreterGuestExecutor::Execute(PPCContext& context, uint8_t* memory_base,
                                                       uint32_t guest_address) {
  uint32_t pc = guest_address;
  uint64_t count = 0;
  while (count < instruction_limit_) {
    if (pc == 0xBCBCBCBC) {
      return {GuestExecutionStatus::kSuccess, pc, 0, count};
    }

    const uint32_t raw = LoadBe32(memory_base + pc);
    const auto instruction = DecodePpcInstruction(raw);
    const uint32_t next_pc = pc + 4;
    ++count;

    switch (instruction.opcode) {
      case PpcOpcode::kAddImmediate:
      case PpcOpcode::kAddImmediateShifted: {
        const uint64_t base = instruction.ra ? Gpr(context, instruction.ra).u64 : 0;
        Gpr(context, instruction.rt).u64 = base + static_cast<int64_t>(instruction.immediate);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kOrImmediate:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 | static_cast<uint32_t>(instruction.immediate);
        pc = next_pc;
        break;
      case PpcOpcode::kXorImmediate:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 ^ static_cast<uint32_t>(instruction.immediate);
        pc = next_pc;
        break;
      case PpcOpcode::kLoadWord: {
        const uint64_t base = instruction.ra ? Gpr(context, instruction.ra).u64 : 0;
        const uint32_t address = static_cast<uint32_t>(base + instruction.immediate);
        Gpr(context, instruction.rt).u64 = LoadBe32(memory_base + address);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreWord: {
        const uint64_t base = instruction.ra ? Gpr(context, instruction.ra).u64 : 0;
        const uint32_t address = static_cast<uint32_t>(base + instruction.immediate);
        StoreBe32(memory_base + address, Gpr(context, instruction.rt).u32);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kBranch:
        if (instruction.link) context.lr = next_pc;
        pc = instruction.absolute ? static_cast<uint32_t>(instruction.immediate)
                                  : static_cast<uint32_t>(pc + instruction.immediate);
        break;
      case PpcOpcode::kBranchConditionalToLinkRegister:
        // BO=20 is the unconditional blr form. Other BO/BI combinations will
        // be added with condition-register support.
        if (instruction.bo != 20) {
          return {GuestExecutionStatus::kFault, pc, raw, count};
        }
        {
          const uint32_t target = static_cast<uint32_t>(context.lr) & ~uint32_t{3};
          if (instruction.link) context.lr = next_pc;
          pc = target;
        }
        break;
      case PpcOpcode::kUnknown:
        return {GuestExecutionStatus::kFault, pc, raw, count};
    }
  }
  return {GuestExecutionStatus::kStopped, pc, 0, count};
}

}  // namespace rex::runtime
