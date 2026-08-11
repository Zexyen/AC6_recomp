#include <bit>
#include <cmath>
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

PPCRegister& Fpr(PPCContext& context, uint8_t index) {
  switch (index) {
#define REX_FPR_CASE(n) case n: return context.f##n
    REX_FPR_CASE(0); REX_FPR_CASE(1); REX_FPR_CASE(2); REX_FPR_CASE(3);
    REX_FPR_CASE(4); REX_FPR_CASE(5); REX_FPR_CASE(6); REX_FPR_CASE(7);
    REX_FPR_CASE(8); REX_FPR_CASE(9); REX_FPR_CASE(10); REX_FPR_CASE(11);
    REX_FPR_CASE(12); REX_FPR_CASE(13); REX_FPR_CASE(14); REX_FPR_CASE(15);
    REX_FPR_CASE(16); REX_FPR_CASE(17); REX_FPR_CASE(18); REX_FPR_CASE(19);
    REX_FPR_CASE(20); REX_FPR_CASE(21); REX_FPR_CASE(22); REX_FPR_CASE(23);
    REX_FPR_CASE(24); REX_FPR_CASE(25); REX_FPR_CASE(26); REX_FPR_CASE(27);
    REX_FPR_CASE(28); REX_FPR_CASE(29); REX_FPR_CASE(30); REX_FPR_CASE(31);
#undef REX_FPR_CASE
    default: return context.f0;
  }
}

uint32_t LoadBe32(const uint8_t* address) {
  uint32_t value;
  std::memcpy(&value, address, sizeof(value));
  return std::byteswap(value);
}

uint16_t LoadBe16(const uint8_t* address) {
  uint16_t value;
  std::memcpy(&value, address, sizeof(value));
  return std::byteswap(value);
}

uint64_t LoadBe64(const uint8_t* address) {
  uint64_t value;
  std::memcpy(&value, address, sizeof(value));
  return std::byteswap(value);
}

void StoreBe32(uint8_t* address, uint32_t value) {
  value = std::byteswap(value);
  std::memcpy(address, &value, sizeof(value));
}

void StoreBe16(uint8_t* address, uint16_t value) {
  value = std::byteswap(value);
  std::memcpy(address, &value, sizeof(value));
}

void StoreBe64(uint8_t* address, uint64_t value) {
  value = std::byteswap(value);
  std::memcpy(address, &value, sizeof(value));
}

uint32_t WordMask(uint8_t begin, uint8_t end) {
  uint32_t mask = 0;
  for (uint8_t bit = 0; bit < 32; ++bit) {
    if (begin <= end ? bit >= begin && bit <= end
                     : bit >= begin || bit <= end) {
      mask |= uint32_t{1} << (31 - bit);
    }
  }
  return mask;
}

struct CarryResult {
  uint64_t value;
  bool carry;
};

CarryResult AddWithCarry(uint64_t left, uint64_t right, bool carry_in) {
  const uint64_t partial = left + right;
  const bool partial_carry = partial < left;
  const uint64_t value = partial + static_cast<uint64_t>(carry_in);
  return {value, partial_carry || (carry_in && value == 0)};
}

bool IsRangeValid(uint32_t address, uint32_t size, uint64_t address_space_size) {
  return static_cast<uint64_t>(address) + size <= address_space_size;
}

uint32_t EffectiveAddress(PPCContext& context, const DecodedPpcInstruction& instruction,
                          bool indexed) {
  const uint64_t base = instruction.ra ? Gpr(context, instruction.ra).u64 : 0;
  return static_cast<uint32_t>(base +
                               (indexed ? Gpr(context, instruction.rb).u64
                                        : static_cast<int64_t>(instruction.immediate)));
}

void UpdateCr0(PPCContext& context, uint64_t value) {
  context.cr0.compare(static_cast<int64_t>(value), int64_t{0}, context.xer);
}

void UpdateCr0Word(PPCContext& context, uint32_t value) {
  context.cr0.compare(static_cast<int32_t>(value), int32_t{0}, context.xer);
}

PPCCRRegister& CrField(PPCContext& context, uint8_t index) {
  switch (index) {
    case 0: return context.cr0;
    case 1: return context.cr1;
    case 2: return context.cr2;
    case 3: return context.cr3;
    case 4: return context.cr4;
    case 5: return context.cr5;
    case 6: return context.cr6;
    default: return context.cr7;
  }
}

bool CrBit(PPCContext& context, uint8_t index) {
  const auto& field = CrField(context, index / 4);
  switch (index & 3) {
    case 0: return field.lt != 0;
    case 1: return field.gt != 0;
    case 2: return field.eq != 0;
    default: return field.so != 0;
  }
}

void SetCrBit(PPCContext& context, uint8_t index, bool value) {
  auto& field = CrField(context, index / 4);
  switch (index & 3) {
    case 0: field.lt = value; break;
    case 1: field.gt = value; break;
    case 2: field.eq = value; break;
    default: field.so = value; break;
  }
}

bool EvaluateCondition(PPCContext& context, uint8_t bo, uint8_t bi) {
  return (bo & 16) != 0 || (CrBit(context, bi) == ((bo & 8) != 0));
}

bool EvaluateBranch(PPCContext& context, uint8_t bo, uint8_t bi) {
  const bool decrement_ctr = (bo & 4) == 0;
  if (decrement_ctr) context.ctr.u64--;
  const bool ctr_ok = (bo & 4) != 0 || ((context.ctr.u64 != 0) != ((bo & 2) != 0));
  const bool condition_ok = EvaluateCondition(context, bo, bi);
  return ctr_ok && condition_ok;
}

bool ReadSpr(PPCContext& context, uint16_t spr, uint64_t& value) {
  switch (spr) {
    case 8: value = context.lr; return true;
    case 9: value = context.ctr.u64; return true;
    default: return false;
  }
}

bool WriteSpr(PPCContext& context, uint16_t spr, uint64_t value) {
  switch (spr) {
    case 8: context.lr = value; return true;
    case 9: context.ctr.u64 = value; return true;
    default: return false;
  }
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

    if (!memory_base || !IsRangeValid(pc, 4, address_space_size_)) {
      return {GuestExecutionStatus::kFault, pc, 0, count};
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
      case PpcOpcode::kAddImmediateCarrying: {
        const auto result = AddWithCarry(
            Gpr(context, instruction.ra).u64,
            static_cast<uint64_t>(static_cast<int64_t>(instruction.immediate)), false);
        Gpr(context, instruction.rt).u64 = result.value;
        context.xer.ca = result.carry;
        if (instruction.record) UpdateCr0(context, result.value);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kSubtractFromImmediateCarrying: {
        const uint64_t source = Gpr(context, instruction.ra).u64;
        const auto result = AddWithCarry(
            ~source, static_cast<uint64_t>(static_cast<int64_t>(instruction.immediate)), true);
        Gpr(context, instruction.rt).u64 = result.value;
        context.xer.ca = result.carry;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kMultiplyLowImmediate:
        Gpr(context, instruction.rt).u64 =
            Gpr(context, instruction.ra).u64 *
            static_cast<uint64_t>(static_cast<int64_t>(instruction.immediate));
        pc = next_pc;
        break;
      case PpcOpcode::kOrImmediate:
      case PpcOpcode::kOrImmediateShifted:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 | static_cast<uint32_t>(instruction.immediate);
        pc = next_pc;
        break;
      case PpcOpcode::kXorImmediate:
      case PpcOpcode::kXorImmediateShifted:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 ^ static_cast<uint32_t>(instruction.immediate);
        pc = next_pc;
        break;
      case PpcOpcode::kAndImmediate:
      case PpcOpcode::kAndImmediateShifted:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 & static_cast<uint32_t>(instruction.immediate);
        UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kLoadWord: {
        const uint32_t address = EffectiveAddress(context, instruction, false);
        if (!IsRangeValid(address, 4, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        Gpr(context, instruction.rt).u64 = LoadBe32(memory_base + address);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadWordUpdate: {
        const uint32_t address = EffectiveAddress(context, instruction, false);
        if (!IsRangeValid(address, 4, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        Gpr(context, instruction.rt).u64 = LoadBe32(memory_base + address);
        Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadWordIndexed:
      case PpcOpcode::kLoadWordIndexedUpdate:
      case PpcOpcode::kLoadWordSignedIndexed:
      case PpcOpcode::kLoadWordSignedIndexedUpdate: {
        const uint32_t address = EffectiveAddress(context, instruction, true);
        if (!IsRangeValid(address, 4, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        const uint32_t value = LoadBe32(memory_base + address);
        const bool signed_load = instruction.opcode == PpcOpcode::kLoadWordSignedIndexed ||
                                 instruction.opcode == PpcOpcode::kLoadWordSignedIndexedUpdate;
        Gpr(context, instruction.rt).u64 = signed_load
            ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(value)))
            : value;
        if (instruction.opcode == PpcOpcode::kLoadWordIndexedUpdate ||
            instruction.opcode == PpcOpcode::kLoadWordSignedIndexedUpdate) {
          Gpr(context, instruction.ra).u64 = address;
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadByte:
      case PpcOpcode::kLoadByteUpdate:
      case PpcOpcode::kLoadByteIndexed:
      case PpcOpcode::kLoadByteIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kLoadByteIndexed ||
                             instruction.opcode == PpcOpcode::kLoadByteIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        if (!IsRangeValid(address, 1, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        Gpr(context, instruction.rt).u64 = memory_base[address];
        if (instruction.opcode == PpcOpcode::kLoadByteUpdate ||
            instruction.opcode == PpcOpcode::kLoadByteIndexedUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadHalf:
      case PpcOpcode::kLoadHalfUpdate:
      case PpcOpcode::kLoadHalfIndexed:
      case PpcOpcode::kLoadHalfSigned:
      case PpcOpcode::kLoadHalfSignedIndexed:
      case PpcOpcode::kLoadHalfIndexedUpdate:
      case PpcOpcode::kLoadHalfSignedIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kLoadHalfIndexed ||
                             instruction.opcode == PpcOpcode::kLoadHalfSignedIndexed ||
                             instruction.opcode == PpcOpcode::kLoadHalfIndexedUpdate ||
                             instruction.opcode == PpcOpcode::kLoadHalfSignedIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        if (!IsRangeValid(address, 2, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        const uint16_t value = LoadBe16(memory_base + address);
        const bool signed_load = instruction.opcode == PpcOpcode::kLoadHalfSigned ||
                                 instruction.opcode == PpcOpcode::kLoadHalfSignedIndexed ||
                                 instruction.opcode == PpcOpcode::kLoadHalfSignedIndexedUpdate;
        Gpr(context, instruction.rt).u64 = signed_load
            ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(value)))
            : value;
        if (instruction.opcode == PpcOpcode::kLoadHalfUpdate ||
            instruction.opcode == PpcOpcode::kLoadHalfIndexedUpdate ||
            instruction.opcode == PpcOpcode::kLoadHalfSignedIndexedUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadDoubleword:
      case PpcOpcode::kLoadDoublewordUpdate:
      case PpcOpcode::kLoadDoublewordIndexed:
      case PpcOpcode::kLoadDoublewordIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kLoadDoublewordIndexed ||
                             instruction.opcode == PpcOpcode::kLoadDoublewordIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        if (!IsRangeValid(address, 8, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        Gpr(context, instruction.rt).u64 = LoadBe64(memory_base + address);
        if (instruction.opcode == PpcOpcode::kLoadDoublewordUpdate ||
            instruction.opcode == PpcOpcode::kLoadDoublewordIndexedUpdate) {
          Gpr(context, instruction.ra).u64 = address;
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadWordAndReserveIndexed:
      case PpcOpcode::kLoadDoublewordAndReserveIndexed: {
        const uint32_t address = EffectiveAddress(context, instruction, true);
        const bool doubleword = instruction.opcode == PpcOpcode::kLoadDoublewordAndReserveIndexed;
        const uint32_t size = doubleword ? 8 : 4;
        if (!IsRangeValid(address, size, address_space_size_)) {
          return {GuestExecutionStatus::kFault, pc, raw, count};
        }
        Gpr(context, instruction.rt).u64 =
            doubleword ? LoadBe64(memory_base + address)
                       : LoadBe32(memory_base + address);
        context.reserved.u64 = (uint64_t{1} << 63) | address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreWord: {
        const uint32_t address = EffectiveAddress(context, instruction, false);
        if (!IsRangeValid(address, 4, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        StoreBe32(memory_base + address, Gpr(context, instruction.rt).u32);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreWordUpdate:
      case PpcOpcode::kStoreWordIndexed:
      case PpcOpcode::kStoreWordIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreWordIndexed ||
                             instruction.opcode == PpcOpcode::kStoreWordIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        if (!IsRangeValid(address, 4, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        StoreBe32(memory_base + address, Gpr(context, instruction.rt).u32);
        if (!indexed || instruction.opcode == PpcOpcode::kStoreWordIndexedUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreByte:
      case PpcOpcode::kStoreByteUpdate:
      case PpcOpcode::kStoreByteIndexed:
      case PpcOpcode::kStoreByteIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreByteIndexed ||
                             instruction.opcode == PpcOpcode::kStoreByteIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        if (!IsRangeValid(address, 1, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        memory_base[address] = Gpr(context, instruction.rt).u8;
        if (instruction.opcode == PpcOpcode::kStoreByteUpdate ||
            instruction.opcode == PpcOpcode::kStoreByteIndexedUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreHalf:
      case PpcOpcode::kStoreHalfUpdate:
      case PpcOpcode::kStoreHalfIndexed:
      case PpcOpcode::kStoreHalfIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreHalfIndexed ||
                             instruction.opcode == PpcOpcode::kStoreHalfIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        if (!IsRangeValid(address, 2, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        StoreBe16(memory_base + address, Gpr(context, instruction.rt).u16);
        if (instruction.opcode == PpcOpcode::kStoreHalfUpdate ||
            instruction.opcode == PpcOpcode::kStoreHalfIndexedUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreDoubleword:
      case PpcOpcode::kStoreDoublewordUpdate:
      case PpcOpcode::kStoreDoublewordIndexed:
      case PpcOpcode::kStoreDoublewordIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreDoublewordIndexed ||
                             instruction.opcode == PpcOpcode::kStoreDoublewordIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        if (!IsRangeValid(address, 8, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        StoreBe64(memory_base + address, Gpr(context, instruction.rt).u64);
        if (instruction.opcode == PpcOpcode::kStoreDoublewordUpdate ||
            instruction.opcode == PpcOpcode::kStoreDoublewordIndexedUpdate) {
          Gpr(context, instruction.ra).u64 = address;
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreWordConditionalIndexed:
      case PpcOpcode::kStoreDoublewordConditionalIndexed: {
        const uint32_t address = EffectiveAddress(context, instruction, true);
        const bool doubleword = instruction.opcode == PpcOpcode::kStoreDoublewordConditionalIndexed;
        const uint32_t size = doubleword ? 8 : 4;
        if (!IsRangeValid(address, size, address_space_size_)) {
          context.reserved.u64 = 0;
          return {GuestExecutionStatus::kFault, pc, raw, count};
        }
        const bool succeeded =
            (context.reserved.u64 & (uint64_t{1} << 63)) != 0 &&
            static_cast<uint32_t>(context.reserved.u64) == address;
        context.reserved.u64 = 0;
        if (succeeded) {
          if (doubleword) StoreBe64(memory_base + address, Gpr(context, instruction.rt).u64);
          else StoreBe32(memory_base + address, Gpr(context, instruction.rt).u32);
        }
        context.cr0.lt = 0;
        context.cr0.gt = 0;
        context.cr0.eq = succeeded;
        context.cr0.so = context.xer.so;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadFloatSingle:
      case PpcOpcode::kLoadFloatSingleUpdate:
      case PpcOpcode::kLoadFloatSingleIndexed:
      case PpcOpcode::kLoadFloatSingleIndexedUpdate:
      case PpcOpcode::kLoadFloatDouble:
      case PpcOpcode::kLoadFloatDoubleUpdate:
      case PpcOpcode::kLoadFloatDoubleIndexed:
      case PpcOpcode::kLoadFloatDoubleIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kLoadFloatSingleIndexed ||
                             instruction.opcode == PpcOpcode::kLoadFloatSingleIndexedUpdate ||
                             instruction.opcode == PpcOpcode::kLoadFloatDoubleIndexed ||
                             instruction.opcode == PpcOpcode::kLoadFloatDoubleIndexedUpdate;
        const bool single = instruction.opcode == PpcOpcode::kLoadFloatSingle ||
                            instruction.opcode == PpcOpcode::kLoadFloatSingleUpdate ||
                            instruction.opcode == PpcOpcode::kLoadFloatSingleIndexed ||
                            instruction.opcode == PpcOpcode::kLoadFloatSingleIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        const uint32_t size = single ? 4 : 8;
        if (!IsRangeValid(address, size, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        if (size == 4) {
          Fpr(context, instruction.rt).f64 = static_cast<double>(std::bit_cast<float>(LoadBe32(memory_base + address)));
        } else {
          Fpr(context, instruction.rt).u64 = LoadBe64(memory_base + address);
        }
        if (instruction.opcode == PpcOpcode::kLoadFloatSingleUpdate ||
            instruction.opcode == PpcOpcode::kLoadFloatSingleIndexedUpdate ||
            instruction.opcode == PpcOpcode::kLoadFloatDoubleUpdate ||
            instruction.opcode == PpcOpcode::kLoadFloatDoubleIndexedUpdate) {
          Gpr(context, instruction.ra).u64 = address;
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreFloatSingle:
      case PpcOpcode::kStoreFloatSingleUpdate:
      case PpcOpcode::kStoreFloatSingleIndexed:
      case PpcOpcode::kStoreFloatSingleIndexedUpdate:
      case PpcOpcode::kStoreFloatDouble:
      case PpcOpcode::kStoreFloatDoubleUpdate:
      case PpcOpcode::kStoreFloatDoubleIndexed:
      case PpcOpcode::kStoreFloatDoubleIndexedUpdate: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreFloatSingleIndexed ||
                             instruction.opcode == PpcOpcode::kStoreFloatSingleIndexedUpdate ||
                             instruction.opcode == PpcOpcode::kStoreFloatDoubleIndexed ||
                             instruction.opcode == PpcOpcode::kStoreFloatDoubleIndexedUpdate;
        const bool single = instruction.opcode == PpcOpcode::kStoreFloatSingle ||
                            instruction.opcode == PpcOpcode::kStoreFloatSingleUpdate ||
                            instruction.opcode == PpcOpcode::kStoreFloatSingleIndexed ||
                            instruction.opcode == PpcOpcode::kStoreFloatSingleIndexedUpdate;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        const uint32_t size = single ? 4 : 8;
        if (!IsRangeValid(address, size, address_space_size_)) return {GuestExecutionStatus::kFault, pc, raw, count};
        if (size == 4) {
          StoreBe32(memory_base + address, std::bit_cast<uint32_t>(static_cast<float>(Fpr(context, instruction.rt).f64)));
        } else {
          StoreBe64(memory_base + address, Fpr(context, instruction.rt).u64);
        }
        if (instruction.opcode == PpcOpcode::kStoreFloatSingleUpdate ||
            instruction.opcode == PpcOpcode::kStoreFloatSingleIndexedUpdate ||
            instruction.opcode == PpcOpcode::kStoreFloatDoubleUpdate ||
            instruction.opcode == PpcOpcode::kStoreFloatDoubleIndexedUpdate) {
          Gpr(context, instruction.ra).u64 = address;
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kBranch:
        if (instruction.link) context.lr = next_pc;
        pc = instruction.absolute ? static_cast<uint32_t>(instruction.immediate)
                                  : static_cast<uint32_t>(pc + instruction.immediate);
        break;
      case PpcOpcode::kBranchConditional:
        if (instruction.link) context.lr = next_pc;
        pc = EvaluateBranch(context, instruction.bo, instruction.bi)
                 ? (instruction.absolute ? static_cast<uint32_t>(instruction.immediate)
                                         : static_cast<uint32_t>(pc + instruction.immediate))
                 : next_pc;
        break;
      case PpcOpcode::kBranchConditionalToLinkRegister:
        // BO=20 is the unconditional blr form. Other BO/BI combinations will
        // be added with condition-register support.
        {
          const uint32_t target = static_cast<uint32_t>(context.lr) & ~uint32_t{3};
          if (instruction.link) context.lr = next_pc;
          pc = EvaluateBranch(context, instruction.bo, instruction.bi) ? target : next_pc;
        }
        break;
      case PpcOpcode::kBranchConditionalToCountRegister: {
        if ((instruction.bo & 4) == 0) {
          return {GuestExecutionStatus::kFault, pc, raw, count};
        }
        const uint32_t target = context.ctr.u32 & ~uint32_t{3};
        if (instruction.link) context.lr = next_pc;
        pc = EvaluateCondition(context, instruction.bo, instruction.bi) ? target : next_pc;
        break;
      }
      case PpcOpcode::kCompareImmediate: {
        auto& field = CrField(context, instruction.cr_field);
        if (instruction.is_64_bit) {
          field.compare(Gpr(context, instruction.ra).s64,
                        static_cast<int64_t>(instruction.immediate), context.xer);
        } else {
          field.compare(Gpr(context, instruction.ra).s32, instruction.immediate, context.xer);
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kCompareLogicalImmediate: {
        auto& field = CrField(context, instruction.cr_field);
        if (instruction.is_64_bit) {
          field.compare(Gpr(context, instruction.ra).u64,
                        static_cast<uint64_t>(static_cast<uint32_t>(instruction.immediate)),
                        context.xer);
        } else {
          field.compare(Gpr(context, instruction.ra).u32,
                        static_cast<uint32_t>(instruction.immediate), context.xer);
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kCompare:
      case PpcOpcode::kCompareLogical: {
        auto& field = CrField(context, instruction.cr_field);
        const bool logical = instruction.opcode == PpcOpcode::kCompareLogical;
        if (instruction.is_64_bit) {
          if (logical) field.compare(Gpr(context, instruction.ra).u64,
                                     Gpr(context, instruction.rb).u64, context.xer);
          else field.compare(Gpr(context, instruction.ra).s64,
                             Gpr(context, instruction.rb).s64, context.xer);
        } else {
          if (logical) field.compare(Gpr(context, instruction.ra).u32,
                                     Gpr(context, instruction.rb).u32, context.xer);
          else field.compare(Gpr(context, instruction.ra).s32,
                             Gpr(context, instruction.rb).s32, context.xer);
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kCrAnd:
      case PpcOpcode::kCrAndComplement:
      case PpcOpcode::kCrEquivalent:
      case PpcOpcode::kCrNand:
      case PpcOpcode::kCrNor:
      case PpcOpcode::kCrOr:
      case PpcOpcode::kCrOrComplement:
      case PpcOpcode::kCrXor: {
        const bool a = CrBit(context, instruction.ra);
        const bool b = CrBit(context, instruction.rb);
        bool value = false;
        switch (instruction.opcode) {
          case PpcOpcode::kCrAnd: value = a && b; break;
          case PpcOpcode::kCrAndComplement: value = a && !b; break;
          case PpcOpcode::kCrEquivalent: value = a == b; break;
          case PpcOpcode::kCrNand: value = !(a && b); break;
          case PpcOpcode::kCrNor: value = !(a || b); break;
          case PpcOpcode::kCrOr: value = a || b; break;
          case PpcOpcode::kCrOrComplement: value = a || !b; break;
          case PpcOpcode::kCrXor: value = a != b; break;
          default: break;
        }
        SetCrBit(context, instruction.rt, value);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kOr:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 | Gpr(context, instruction.rb).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kXor:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 ^ Gpr(context, instruction.rb).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kAnd:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 & Gpr(context, instruction.rb).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kAndComplement:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 & ~Gpr(context, instruction.rb).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kOrComplement:
        Gpr(context, instruction.ra).u64 =
            Gpr(context, instruction.rt).u64 | ~Gpr(context, instruction.rb).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kNand:
        Gpr(context, instruction.ra).u64 =
            ~(Gpr(context, instruction.rt).u64 & Gpr(context, instruction.rb).u64);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kNor:
        Gpr(context, instruction.ra).u64 =
            ~(Gpr(context, instruction.rt).u64 | Gpr(context, instruction.rb).u64);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kEquivalent:
        Gpr(context, instruction.ra).u64 =
            ~(Gpr(context, instruction.rt).u64 ^ Gpr(context, instruction.rb).u64);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kAdd:
        Gpr(context, instruction.rt).u64 =
            Gpr(context, instruction.ra).u64 + Gpr(context, instruction.rb).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kAddCarrying:
      case PpcOpcode::kAddExtended:
      case PpcOpcode::kAddToMinusOneExtended:
      case PpcOpcode::kAddToZeroExtended: {
        const uint64_t left = Gpr(context, instruction.ra).u64;
        uint64_t right = 0;
        bool carry_in = false;
        if (instruction.opcode == PpcOpcode::kAddCarrying ||
            instruction.opcode == PpcOpcode::kAddExtended) {
          right = Gpr(context, instruction.rb).u64;
        } else if (instruction.opcode == PpcOpcode::kAddToMinusOneExtended) {
          right = UINT64_MAX;
        }
        if (instruction.opcode != PpcOpcode::kAddCarrying) carry_in = context.xer.ca != 0;
        const auto result = AddWithCarry(left, right, carry_in);
        Gpr(context, instruction.rt).u64 = result.value;
        context.xer.ca = result.carry;
        if (instruction.record) UpdateCr0(context, result.value);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kSubtractFrom:
        Gpr(context, instruction.rt).u64 =
            Gpr(context, instruction.rb).u64 - Gpr(context, instruction.ra).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kSubtractFromCarrying:
      case PpcOpcode::kSubtractFromExtended:
      case PpcOpcode::kSubtractFromMinusOneExtended:
      case PpcOpcode::kSubtractFromZeroExtended: {
        const uint64_t left = ~Gpr(context, instruction.ra).u64;
        uint64_t right = 0;
        bool carry_in = true;
        if (instruction.opcode == PpcOpcode::kSubtractFromCarrying ||
            instruction.opcode == PpcOpcode::kSubtractFromExtended) {
          right = Gpr(context, instruction.rb).u64;
        } else if (instruction.opcode == PpcOpcode::kSubtractFromMinusOneExtended) {
          right = UINT64_MAX;
        }
        if (instruction.opcode != PpcOpcode::kSubtractFromCarrying) {
          carry_in = context.xer.ca != 0;
        }
        const auto result = AddWithCarry(left, right, carry_in);
        Gpr(context, instruction.rt).u64 = result.value;
        context.xer.ca = result.carry;
        if (instruction.record) UpdateCr0(context, result.value);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kNegate:
        Gpr(context, instruction.rt).u64 = uint64_t{0} - Gpr(context, instruction.ra).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kSignExtendByte:
        Gpr(context, instruction.ra).s64 = static_cast<int8_t>(Gpr(context, instruction.rt).u8);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kSignExtendHalfword:
        Gpr(context, instruction.ra).s64 = static_cast<int16_t>(Gpr(context, instruction.rt).u16);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kSignExtendWord:
        Gpr(context, instruction.ra).s64 = static_cast<int32_t>(Gpr(context, instruction.rt).u32);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kCountLeadingZerosWord:
        Gpr(context, instruction.ra).u64 = std::countl_zero(Gpr(context, instruction.rt).u32);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kCountLeadingZerosDoubleword:
        Gpr(context, instruction.ra).u64 = std::countl_zero(Gpr(context, instruction.rt).u64);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kMultiplyLowWord:
        Gpr(context, instruction.rt).s64 = static_cast<int32_t>(
            Gpr(context, instruction.ra).u32 * Gpr(context, instruction.rb).u32);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kMultiplyLowDoubleword:
        Gpr(context, instruction.rt).u64 =
            Gpr(context, instruction.ra).u64 * Gpr(context, instruction.rb).u64;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kMultiplyHighWord:
        Gpr(context, instruction.rt).s64 =
            (static_cast<int64_t>(Gpr(context, instruction.ra).s32) *
             static_cast<int64_t>(Gpr(context, instruction.rb).s32)) >> 32;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kMultiplyHighWordUnsigned:
        Gpr(context, instruction.rt).u64 =
            (static_cast<uint64_t>(Gpr(context, instruction.ra).u32) *
             static_cast<uint64_t>(Gpr(context, instruction.rb).u32)) >> 32;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kMultiplyHighDoubleword:
        Gpr(context, instruction.rt).s64 = static_cast<int64_t>(
            (static_cast<__int128>(Gpr(context, instruction.ra).s64) *
             static_cast<__int128>(Gpr(context, instruction.rb).s64)) >> 64);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kMultiplyHighDoublewordUnsigned:
        Gpr(context, instruction.rt).u64 = static_cast<uint64_t>(
            (static_cast<__uint128_t>(Gpr(context, instruction.ra).u64) *
             static_cast<__uint128_t>(Gpr(context, instruction.rb).u64)) >> 64);
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.rt).u64);
        pc = next_pc;
        break;
      case PpcOpcode::kDivideWord:
      case PpcOpcode::kDivideWordUnsigned:
      case PpcOpcode::kDivideDoubleword:
      case PpcOpcode::kDivideDoublewordUnsigned: {
        auto& destination = Gpr(context, instruction.rt);
        const auto& dividend = Gpr(context, instruction.ra);
        const auto& divisor = Gpr(context, instruction.rb);
        if (instruction.opcode == PpcOpcode::kDivideWord) {
          destination.s64 = divisor.s32 == 0 ||
                                    (dividend.s32 == INT32_MIN && divisor.s32 == -1)
                                ? 0
                                : dividend.s32 / divisor.s32;
        } else if (instruction.opcode == PpcOpcode::kDivideWordUnsigned) {
          destination.u64 = divisor.u32 == 0 ? 0 : dividend.u32 / divisor.u32;
        } else if (instruction.opcode == PpcOpcode::kDivideDoubleword) {
          destination.s64 = divisor.s64 == 0 ||
                                    (dividend.s64 == INT64_MIN && divisor.s64 == -1)
                                ? 0
                                : dividend.s64 / divisor.s64;
        } else {
          destination.u64 = divisor.u64 == 0 ? 0 : dividend.u64 / divisor.u64;
        }
        if (instruction.record) UpdateCr0(context, destination.u64);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kRotateLeftWordImmediateAndMask:
      case PpcOpcode::kRotateLeftWordAndMask: {
        const uint32_t shift = instruction.opcode == PpcOpcode::kRotateLeftWordAndMask
                                   ? Gpr(context, instruction.rb).u32 & 31
                                   : instruction.shift;
        const uint32_t value = std::rotl(Gpr(context, instruction.rt).u32, shift) &
                               WordMask(instruction.mask_begin, instruction.mask_end);
        Gpr(context, instruction.ra).u64 = value;
        if (instruction.record) UpdateCr0Word(context, value);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kRotateLeftWordImmediateMaskInsert: {
        const uint32_t mask = WordMask(instruction.mask_begin, instruction.mask_end);
        const uint32_t value =
            (std::rotl(Gpr(context, instruction.rt).u32, instruction.shift) & mask) |
            (Gpr(context, instruction.ra).u32 & ~mask);
        Gpr(context, instruction.ra).u64 = value;
        if (instruction.record) UpdateCr0Word(context, value);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kShiftLeftWord:
      case PpcOpcode::kShiftRightWord: {
        const uint32_t shift = Gpr(context, instruction.rb).u32 & 63;
        uint32_t value = 0;
        if (shift < 32) {
          value = instruction.opcode == PpcOpcode::kShiftLeftWord
                      ? Gpr(context, instruction.rt).u32 << shift
                      : Gpr(context, instruction.rt).u32 >> shift;
        }
        Gpr(context, instruction.ra).u64 = value;
        if (instruction.record) UpdateCr0Word(context, value);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kShiftRightArithmeticWord:
      case PpcOpcode::kShiftRightArithmeticWordImmediate: {
        const uint32_t requested_shift =
            instruction.opcode == PpcOpcode::kShiftRightArithmeticWordImmediate
                ? instruction.shift
                : Gpr(context, instruction.rb).u32 & 63;
        const uint32_t shift = requested_shift > 31 ? 31 : requested_shift;
        const int32_t source = Gpr(context, instruction.rt).s32;
        const uint32_t discarded_mask = shift == 0 ? 0 : (uint32_t{1} << shift) - 1;
        context.xer.ca = source < 0 && (Gpr(context, instruction.rt).u32 & discarded_mask) != 0;
        Gpr(context, instruction.ra).s64 = source >> shift;
        if (instruction.record) UpdateCr0(context, Gpr(context, instruction.ra).u64);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kShiftLeftDoubleword:
      case PpcOpcode::kShiftRightDoubleword: {
        const uint32_t shift = Gpr(context, instruction.rb).u32 & 127;
        uint64_t value = 0;
        if (shift < 64) {
          value = instruction.opcode == PpcOpcode::kShiftLeftDoubleword
                      ? Gpr(context, instruction.rt).u64 << shift
                      : Gpr(context, instruction.rt).u64 >> shift;
        }
        Gpr(context, instruction.ra).u64 = value;
        if (instruction.record) UpdateCr0(context, value);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kFloatMove:
        Fpr(context, instruction.rt).u64 = Fpr(context, instruction.rb).u64;
        pc = next_pc;
        break;
      case PpcOpcode::kFloatAbsolute:
        Fpr(context, instruction.rt).u64 = Fpr(context, instruction.rb).u64 & ~(uint64_t{1} << 63);
        pc = next_pc;
        break;
      case PpcOpcode::kFloatNegativeAbsolute:
        Fpr(context, instruction.rt).u64 = Fpr(context, instruction.rb).u64 | (uint64_t{1} << 63);
        pc = next_pc;
        break;
      case PpcOpcode::kFloatNegate:
        Fpr(context, instruction.rt).u64 = Fpr(context, instruction.rb).u64 ^ (uint64_t{1} << 63);
        pc = next_pc;
        break;
      case PpcOpcode::kFloatAdd:
      case PpcOpcode::kFloatSubtract:
      case PpcOpcode::kFloatMultiply:
      case PpcOpcode::kFloatDivide: {
        const double left = Fpr(context, instruction.ra).f64;
        const double right = Fpr(context, instruction.rb).f64;
        double value = 0;
        if (instruction.opcode == PpcOpcode::kFloatAdd) value = left + right;
        else if (instruction.opcode == PpcOpcode::kFloatSubtract) value = left - right;
        else if (instruction.opcode == PpcOpcode::kFloatMultiply) value = left * right;
        else value = left / right;
        Fpr(context, instruction.rt).f64 = instruction.is_64_bit ? value : static_cast<double>(static_cast<float>(value));
        pc = next_pc;
        break;
      }
      case PpcOpcode::kFloatMultiplyAdd:
      case PpcOpcode::kFloatMultiplySubtract:
      case PpcOpcode::kFloatNegativeMultiplyAdd:
      case PpcOpcode::kFloatNegativeMultiplySubtract: {
        const double product_and_addend = std::fma(
            Fpr(context, instruction.ra).f64,
            Fpr(context, instruction.rc).f64,
            (instruction.opcode == PpcOpcode::kFloatMultiplySubtract ||
             instruction.opcode == PpcOpcode::kFloatNegativeMultiplySubtract)
                ? -Fpr(context, instruction.rb).f64
                : Fpr(context, instruction.rb).f64);
        const double value =
            (instruction.opcode == PpcOpcode::kFloatNegativeMultiplyAdd ||
             instruction.opcode == PpcOpcode::kFloatNegativeMultiplySubtract)
                ? -product_and_addend
                : product_and_addend;
        Fpr(context, instruction.rt).f64 =
            instruction.is_64_bit
                ? value
                : static_cast<double>(static_cast<float>(value));
        pc = next_pc;
        break;
      }
      case PpcOpcode::kFloatSelect:
        Fpr(context, instruction.rt).f64 =
            Fpr(context, instruction.ra).f64 >= 0.0
                ? Fpr(context, instruction.rc).f64
                : Fpr(context, instruction.rb).f64;
        pc = next_pc;
        break;
      case PpcOpcode::kFloatCompare:
        CrField(context, instruction.cr_field).compare(
            Fpr(context, instruction.ra).f64, Fpr(context, instruction.rb).f64);
        pc = next_pc;
        break;
      case PpcOpcode::kFloatRoundToSingle:
        Fpr(context, instruction.rt).f64 = static_cast<double>(static_cast<float>(Fpr(context, instruction.rb).f64));
        pc = next_pc;
        break;
      case PpcOpcode::kFloatConvertFromIntegerDoubleword:
        Fpr(context, instruction.rt).f64 = static_cast<double>(Fpr(context, instruction.rb).s64);
        pc = next_pc;
        break;
      case PpcOpcode::kFloatConvertToIntegerWordZero:
        if (std::isnan(Fpr(context, instruction.rb).f64)) {
          Fpr(context, instruction.rt).s64 = INT32_MIN;
        } else if (Fpr(context, instruction.rb).f64 >= static_cast<double>(INT32_MAX)) {
          Fpr(context, instruction.rt).s64 = INT32_MAX;
        } else if (Fpr(context, instruction.rb).f64 <= static_cast<double>(INT32_MIN)) {
          Fpr(context, instruction.rt).s64 = INT32_MIN;
        } else {
          Fpr(context, instruction.rt).s64 = static_cast<int32_t>(Fpr(context, instruction.rb).f64);
        }
        pc = next_pc;
        break;
      case PpcOpcode::kFloatConvertToIntegerDoublewordZero:
        if (std::isnan(Fpr(context, instruction.rb).f64)) {
          Fpr(context, instruction.rt).s64 = INT64_MIN;
        } else if (Fpr(context, instruction.rb).f64 >= static_cast<double>(INT64_MAX)) {
          Fpr(context, instruction.rt).s64 = INT64_MAX;
        } else if (Fpr(context, instruction.rb).f64 <= static_cast<double>(INT64_MIN)) {
          Fpr(context, instruction.rt).s64 = INT64_MIN;
        } else {
          Fpr(context, instruction.rt).s64 = static_cast<int64_t>(Fpr(context, instruction.rb).f64);
        }
        pc = next_pc;
        break;
      case PpcOpcode::kMoveFromSpr: {
        uint64_t value = 0;
        if (!ReadSpr(context, instruction.spr, value)) {
          return {GuestExecutionStatus::kFault, pc, raw, count};
        }
        Gpr(context, instruction.rt).u64 = value;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kMoveToSpr:
        if (!WriteSpr(context, instruction.spr, Gpr(context, instruction.rt).u64)) {
          return {GuestExecutionStatus::kFault, pc, raw, count};
        }
        pc = next_pc;
        break;
      case PpcOpcode::kUnknown:
        return {GuestExecutionStatus::kFault, pc, raw, count};
    }
  }
  return {GuestExecutionStatus::kStopped, pc, 0, count};
}

}  // namespace rex::runtime
