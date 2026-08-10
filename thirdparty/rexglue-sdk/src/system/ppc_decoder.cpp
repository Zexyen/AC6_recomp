#include <rex/system/ppc_decoder.h>

namespace rex::runtime {
namespace {

constexpr int32_t SignExtend(uint32_t value, unsigned bits) {
  const uint32_t sign = uint32_t{1} << (bits - 1);
  return static_cast<int32_t>((value ^ sign) - sign);
}

}  // namespace

DecodedPpcInstruction DecodePpcInstruction(uint32_t raw) {
  DecodedPpcInstruction result{};
  result.raw = raw;
  result.rt = static_cast<uint8_t>((raw >> 21) & 31);
  result.ra = static_cast<uint8_t>((raw >> 16) & 31);
  result.rb = static_cast<uint8_t>((raw >> 11) & 31);

  switch (raw >> 26) {
    case 14:
      result.opcode = PpcOpcode::kAddImmediate;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 15:
      result.opcode = PpcOpcode::kAddImmediateShifted;
      result.immediate = SignExtend(raw & 0xFFFF, 16) * 65536;
      break;
    case 24:
      result.opcode = PpcOpcode::kOrImmediate;
      result.immediate = static_cast<int32_t>(raw & 0xFFFF);
      break;
    case 26:
      result.opcode = PpcOpcode::kXorImmediate;
      result.immediate = static_cast<int32_t>(raw & 0xFFFF);
      break;
    case 32:
      result.opcode = PpcOpcode::kLoadWord;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 33:
      result.opcode = PpcOpcode::kLoadWordUpdate;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 34:
      result.opcode = PpcOpcode::kLoadByte;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 35:
      result.opcode = PpcOpcode::kLoadByteUpdate;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 36:
      result.opcode = PpcOpcode::kStoreWord;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 37:
      result.opcode = PpcOpcode::kStoreWordUpdate;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 38:
      result.opcode = PpcOpcode::kStoreByte;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 39:
      result.opcode = PpcOpcode::kStoreByteUpdate;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 40:
      result.opcode = PpcOpcode::kLoadHalf;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 41:
      result.opcode = PpcOpcode::kLoadHalfUpdate;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 42:
      result.opcode = PpcOpcode::kLoadHalfSigned;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 44:
      result.opcode = PpcOpcode::kStoreHalf;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 45:
      result.opcode = PpcOpcode::kStoreHalfUpdate;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 18:
      result.opcode = PpcOpcode::kBranch;
      result.immediate = SignExtend(raw & 0x03FFFFFC, 26);
      result.absolute = (raw & 2) != 0;
      result.link = (raw & 1) != 0;
      break;
    case 16:
      result.opcode = PpcOpcode::kBranchConditional;
      result.bo = static_cast<uint8_t>((raw >> 21) & 31);
      result.bi = static_cast<uint8_t>((raw >> 16) & 31);
      result.immediate = SignExtend(raw & 0xFFFC, 16);
      result.absolute = (raw & 2) != 0;
      result.link = (raw & 1) != 0;
      break;
    case 11:
      result.opcode = PpcOpcode::kCompareImmediate;
      result.cr_field = static_cast<uint8_t>((raw >> 23) & 7);
      result.is_64_bit = ((raw >> 21) & 1) != 0;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 10:
      result.opcode = PpcOpcode::kCompareLogicalImmediate;
      result.cr_field = static_cast<uint8_t>((raw >> 23) & 7);
      result.is_64_bit = ((raw >> 21) & 1) != 0;
      result.immediate = static_cast<int32_t>(raw & 0xFFFF);
      break;
    case 19:
      if (((raw >> 1) & 0x3FF) == 16) {
        result.opcode = PpcOpcode::kBranchConditionalToLinkRegister;
        result.bo = static_cast<uint8_t>((raw >> 21) & 31);
        result.bi = static_cast<uint8_t>((raw >> 16) & 31);
        result.link = (raw & 1) != 0;
      }
      break;
    case 31: {
      const uint32_t xo = (raw >> 1) & 0x3FF;
      result.record = (raw & 1) != 0;
      switch (xo) {
        case 23: result.opcode = PpcOpcode::kLoadWordIndexed; break;
        case 87: result.opcode = PpcOpcode::kLoadByteIndexed; break;
        case 279: result.opcode = PpcOpcode::kLoadHalfIndexed; break;
        case 343: result.opcode = PpcOpcode::kLoadHalfSignedIndexed; break;
        case 151: result.opcode = PpcOpcode::kStoreWordIndexed; break;
        case 215: result.opcode = PpcOpcode::kStoreByteIndexed; break;
        case 407: result.opcode = PpcOpcode::kStoreHalfIndexed; break;
        case 28: result.opcode = PpcOpcode::kAnd; break;
        case 316: result.opcode = PpcOpcode::kXor; break;
        case 444: result.opcode = PpcOpcode::kOr; break;
        case 266: result.opcode = PpcOpcode::kAdd; break;
        case 40: result.opcode = PpcOpcode::kSubtractFrom; break;
        case 104: result.opcode = PpcOpcode::kNegate; break;
        case 339:
          result.opcode = PpcOpcode::kMoveFromSpr;
          result.spr = static_cast<uint16_t>(((raw >> 16) & 31) | (((raw >> 11) & 31) << 5));
          break;
        case 467:
          result.opcode = PpcOpcode::kMoveToSpr;
          result.spr = static_cast<uint16_t>(((raw >> 16) & 31) | (((raw >> 11) & 31) << 5));
          break;
        default: break;
      }
      break;
    }
    default:
      break;
  }
  return result;
}

}  // namespace rex::runtime
