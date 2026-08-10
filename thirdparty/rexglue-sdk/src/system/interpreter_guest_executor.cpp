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
        const uint32_t address = EffectiveAddress(context, instruction, false);
        Gpr(context, instruction.rt).u64 = LoadBe32(memory_base + address);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadWordUpdate: {
        const uint32_t address = EffectiveAddress(context, instruction, false);
        Gpr(context, instruction.rt).u64 = LoadBe32(memory_base + address);
        Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadWordIndexed:
        Gpr(context, instruction.rt).u64 =
            LoadBe32(memory_base + EffectiveAddress(context, instruction, true));
        pc = next_pc;
        break;
      case PpcOpcode::kLoadByte:
      case PpcOpcode::kLoadByteUpdate:
      case PpcOpcode::kLoadByteIndexed: {
        const bool indexed = instruction.opcode == PpcOpcode::kLoadByteIndexed;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        Gpr(context, instruction.rt).u64 = memory_base[address];
        if (instruction.opcode == PpcOpcode::kLoadByteUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadHalf:
      case PpcOpcode::kLoadHalfUpdate:
      case PpcOpcode::kLoadHalfIndexed:
      case PpcOpcode::kLoadHalfSigned:
      case PpcOpcode::kLoadHalfSignedIndexed: {
        const bool indexed = instruction.opcode == PpcOpcode::kLoadHalfIndexed ||
                             instruction.opcode == PpcOpcode::kLoadHalfSignedIndexed;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        const uint16_t value = LoadBe16(memory_base + address);
        const bool signed_load = instruction.opcode == PpcOpcode::kLoadHalfSigned ||
                                 instruction.opcode == PpcOpcode::kLoadHalfSignedIndexed;
        Gpr(context, instruction.rt).u64 = signed_load
            ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(value)))
            : value;
        if (instruction.opcode == PpcOpcode::kLoadHalfUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kLoadDoubleword:
      case PpcOpcode::kLoadDoublewordUpdate:
      case PpcOpcode::kLoadDoublewordIndexed: {
        const bool indexed = instruction.opcode == PpcOpcode::kLoadDoublewordIndexed;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        Gpr(context, instruction.rt).u64 = LoadBe64(memory_base + address);
        if (instruction.opcode == PpcOpcode::kLoadDoublewordUpdate) {
          Gpr(context, instruction.ra).u64 = address;
        }
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreWord: {
        const uint32_t address = EffectiveAddress(context, instruction, false);
        StoreBe32(memory_base + address, Gpr(context, instruction.rt).u32);
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreWordUpdate:
      case PpcOpcode::kStoreWordIndexed: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreWordIndexed;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        StoreBe32(memory_base + address, Gpr(context, instruction.rt).u32);
        if (!indexed) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreByte:
      case PpcOpcode::kStoreByteUpdate:
      case PpcOpcode::kStoreByteIndexed: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreByteIndexed;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        memory_base[address] = Gpr(context, instruction.rt).u8;
        if (instruction.opcode == PpcOpcode::kStoreByteUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreHalf:
      case PpcOpcode::kStoreHalfUpdate:
      case PpcOpcode::kStoreHalfIndexed: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreHalfIndexed;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        StoreBe16(memory_base + address, Gpr(context, instruction.rt).u16);
        if (instruction.opcode == PpcOpcode::kStoreHalfUpdate) Gpr(context, instruction.ra).u64 = address;
        pc = next_pc;
        break;
      }
      case PpcOpcode::kStoreDoubleword:
      case PpcOpcode::kStoreDoublewordUpdate:
      case PpcOpcode::kStoreDoublewordIndexed: {
        const bool indexed = instruction.opcode == PpcOpcode::kStoreDoublewordIndexed;
        const uint32_t address = EffectiveAddress(context, instruction, indexed);
        StoreBe64(memory_base + address, Gpr(context, instruction.rt).u64);
        if (instruction.opcode == PpcOpcode::kStoreDoublewordUpdate) {
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
