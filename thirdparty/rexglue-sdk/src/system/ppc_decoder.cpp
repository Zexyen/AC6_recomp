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
    case 8:
      result.opcode = PpcOpcode::kSubtractFromImmediateCarrying;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 12:
    case 13:
      result.opcode = PpcOpcode::kAddImmediateCarrying;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      result.record = (raw >> 26) == 13;
      break;
    case 7:
      result.opcode = PpcOpcode::kMultiplyLowImmediate;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
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
    case 25:
      result.opcode = PpcOpcode::kOrImmediateShifted;
      result.immediate = static_cast<int32_t>((raw & 0xFFFF) << 16);
      break;
    case 26:
      result.opcode = PpcOpcode::kXorImmediate;
      result.immediate = static_cast<int32_t>(raw & 0xFFFF);
      break;
    case 27:
      result.opcode = PpcOpcode::kXorImmediateShifted;
      result.immediate = static_cast<int32_t>((raw & 0xFFFF) << 16);
      break;
    case 28:
      result.opcode = PpcOpcode::kAndImmediate;
      result.immediate = static_cast<int32_t>(raw & 0xFFFF);
      result.record = true;
      break;
    case 29:
      result.opcode = PpcOpcode::kAndImmediateShifted;
      result.immediate = static_cast<int32_t>((raw & 0xFFFF) << 16);
      result.record = true;
      break;
    case 21:
      result.opcode = PpcOpcode::kRotateLeftWordImmediateAndMask;
      result.shift = static_cast<uint8_t>((raw >> 11) & 31);
      result.mask_begin = static_cast<uint8_t>((raw >> 6) & 31);
      result.mask_end = static_cast<uint8_t>((raw >> 1) & 31);
      result.record = (raw & 1) != 0;
      break;
    case 20:
      result.opcode = PpcOpcode::kRotateLeftWordImmediateMaskInsert;
      result.shift = static_cast<uint8_t>((raw >> 11) & 31);
      result.mask_begin = static_cast<uint8_t>((raw >> 6) & 31);
      result.mask_end = static_cast<uint8_t>((raw >> 1) & 31);
      result.record = (raw & 1) != 0;
      break;
    case 23:
      result.opcode = PpcOpcode::kRotateLeftWordAndMask;
      result.mask_begin = static_cast<uint8_t>((raw >> 6) & 31);
      result.mask_end = static_cast<uint8_t>((raw >> 1) & 31);
      result.record = (raw & 1) != 0;
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
    case 48:
      result.opcode = PpcOpcode::kLoadFloatSingle;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 50:
      result.opcode = PpcOpcode::kLoadFloatDouble;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 52:
      result.opcode = PpcOpcode::kStoreFloatSingle;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 54:
      result.opcode = PpcOpcode::kStoreFloatDouble;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 59: {
      const uint32_t xo = (raw >> 1) & 31;
      switch (xo) {
        case 18: result.opcode = PpcOpcode::kFloatDivide; break;
        case 20: result.opcode = PpcOpcode::kFloatSubtract; break;
        case 21: result.opcode = PpcOpcode::kFloatAdd; break;
        case 25:
          result.opcode = PpcOpcode::kFloatMultiply;
          result.rb = static_cast<uint8_t>((raw >> 6) & 31);
          break;
        default: break;
      }
      result.is_64_bit = false;
      break;
    }
    case 63: {
      const uint32_t xo = (raw >> 1) & 0x3FF;
      switch (xo) {
        case 0:
        case 32:
          result.opcode = PpcOpcode::kFloatCompare;
          result.cr_field = static_cast<uint8_t>((raw >> 23) & 7);
          break;
        case 40: result.opcode = PpcOpcode::kFloatNegate; break;
        case 72: result.opcode = PpcOpcode::kFloatMove; break;
        case 136: result.opcode = PpcOpcode::kFloatNegativeAbsolute; break;
        case 264: result.opcode = PpcOpcode::kFloatAbsolute; break;
        default: break;
      }
      if (result.opcode == PpcOpcode::kUnknown) {
        switch ((raw >> 1) & 31) {
          case 18: result.opcode = PpcOpcode::kFloatDivide; break;
          case 20: result.opcode = PpcOpcode::kFloatSubtract; break;
          case 21: result.opcode = PpcOpcode::kFloatAdd; break;
          case 25:
            result.opcode = PpcOpcode::kFloatMultiply;
            result.rb = static_cast<uint8_t>((raw >> 6) & 31);
            break;
          default: break;
        }
      }
      result.is_64_bit = true;
      break;
    }
    case 58:
      result.immediate = SignExtend(raw & 0xFFFC, 16);
      switch (raw & 3) {
        case 0: result.opcode = PpcOpcode::kLoadDoubleword; break;
        case 1: result.opcode = PpcOpcode::kLoadDoublewordUpdate; break;
        default: break;
      }
      break;
    case 62:
      result.immediate = SignExtend(raw & 0xFFFC, 16);
      switch (raw & 3) {
        case 0: result.opcode = PpcOpcode::kStoreDoubleword; break;
        case 1: result.opcode = PpcOpcode::kStoreDoublewordUpdate; break;
        default: break;
      }
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
      result.bo = static_cast<uint8_t>((raw >> 21) & 31);
      result.bi = static_cast<uint8_t>((raw >> 16) & 31);
      result.link = (raw & 1) != 0;
      switch ((raw >> 1) & 0x3FF) {
        case 16: result.opcode = PpcOpcode::kBranchConditionalToLinkRegister; break;
        case 528: result.opcode = PpcOpcode::kBranchConditionalToCountRegister; break;
        case 257: result.opcode = PpcOpcode::kCrAnd; break;
        case 129: result.opcode = PpcOpcode::kCrAndComplement; break;
        case 289: result.opcode = PpcOpcode::kCrEquivalent; break;
        case 225: result.opcode = PpcOpcode::kCrNand; break;
        case 33: result.opcode = PpcOpcode::kCrNor; break;
        case 449: result.opcode = PpcOpcode::kCrOr; break;
        case 417: result.opcode = PpcOpcode::kCrOrComplement; break;
        case 193: result.opcode = PpcOpcode::kCrXor; break;
        default: break;
      }
      break;
    case 31: {
      const uint32_t xo = (raw >> 1) & 0x3FF;
      result.record = (raw & 1) != 0;
      switch (xo) {
        case 0:
          result.opcode = PpcOpcode::kCompare;
          result.cr_field = static_cast<uint8_t>((raw >> 23) & 7);
          result.is_64_bit = ((raw >> 21) & 1) != 0;
          break;
        case 32:
          result.opcode = PpcOpcode::kCompareLogical;
          result.cr_field = static_cast<uint8_t>((raw >> 23) & 7);
          result.is_64_bit = ((raw >> 21) & 1) != 0;
          break;
        case 23: result.opcode = PpcOpcode::kLoadWordIndexed; break;
        case 55: result.opcode = PpcOpcode::kLoadWordIndexedUpdate; break;
        case 341: result.opcode = PpcOpcode::kLoadWordSignedIndexed; break;
        case 373: result.opcode = PpcOpcode::kLoadWordSignedIndexedUpdate; break;
        case 87: result.opcode = PpcOpcode::kLoadByteIndexed; break;
        case 119: result.opcode = PpcOpcode::kLoadByteIndexedUpdate; break;
        case 279: result.opcode = PpcOpcode::kLoadHalfIndexed; break;
        case 311: result.opcode = PpcOpcode::kLoadHalfIndexedUpdate; break;
        case 343: result.opcode = PpcOpcode::kLoadHalfSignedIndexed; break;
        case 375: result.opcode = PpcOpcode::kLoadHalfSignedIndexedUpdate; break;
        case 21: result.opcode = PpcOpcode::kLoadDoublewordIndexed; break;
        case 53: result.opcode = PpcOpcode::kLoadDoublewordIndexedUpdate; break;
        case 151: result.opcode = PpcOpcode::kStoreWordIndexed; break;
        case 183: result.opcode = PpcOpcode::kStoreWordIndexedUpdate; break;
        case 215: result.opcode = PpcOpcode::kStoreByteIndexed; break;
        case 247: result.opcode = PpcOpcode::kStoreByteIndexedUpdate; break;
        case 407: result.opcode = PpcOpcode::kStoreHalfIndexed; break;
        case 439: result.opcode = PpcOpcode::kStoreHalfIndexedUpdate; break;
        case 149: result.opcode = PpcOpcode::kStoreDoublewordIndexed; break;
        case 181: result.opcode = PpcOpcode::kStoreDoublewordIndexedUpdate; break;
        case 24: result.opcode = PpcOpcode::kShiftLeftWord; break;
        case 536: result.opcode = PpcOpcode::kShiftRightWord; break;
        case 27: result.opcode = PpcOpcode::kShiftLeftDoubleword; break;
        case 539: result.opcode = PpcOpcode::kShiftRightDoubleword; break;
        case 28: result.opcode = PpcOpcode::kAnd; break;
        case 60: result.opcode = PpcOpcode::kAndComplement; break;
        case 412: result.opcode = PpcOpcode::kOrComplement; break;
        case 476: result.opcode = PpcOpcode::kNand; break;
        case 124: result.opcode = PpcOpcode::kNor; break;
        case 284: result.opcode = PpcOpcode::kEquivalent; break;
        case 316: result.opcode = PpcOpcode::kXor; break;
        case 444: result.opcode = PpcOpcode::kOr; break;
        case 792: result.opcode = PpcOpcode::kShiftRightArithmeticWord; break;
        case 824:
          result.opcode = PpcOpcode::kShiftRightArithmeticWordImmediate;
          result.shift = result.rb;
          break;
        case 266: result.opcode = PpcOpcode::kAdd; break;
        case 10: result.opcode = PpcOpcode::kAddCarrying; break;
        case 138: result.opcode = PpcOpcode::kAddExtended; break;
        case 234: result.opcode = PpcOpcode::kAddToMinusOneExtended; break;
        case 202: result.opcode = PpcOpcode::kAddToZeroExtended; break;
        case 40: result.opcode = PpcOpcode::kSubtractFrom; break;
        case 8: result.opcode = PpcOpcode::kSubtractFromCarrying; break;
        case 136: result.opcode = PpcOpcode::kSubtractFromExtended; break;
        case 232: result.opcode = PpcOpcode::kSubtractFromMinusOneExtended; break;
        case 200: result.opcode = PpcOpcode::kSubtractFromZeroExtended; break;
        case 104: result.opcode = PpcOpcode::kNegate; break;
        case 954: result.opcode = PpcOpcode::kSignExtendByte; break;
        case 922: result.opcode = PpcOpcode::kSignExtendHalfword; break;
        case 986: result.opcode = PpcOpcode::kSignExtendWord; break;
        case 26: result.opcode = PpcOpcode::kCountLeadingZerosWord; break;
        case 58: result.opcode = PpcOpcode::kCountLeadingZerosDoubleword; break;
        case 235: result.opcode = PpcOpcode::kMultiplyLowWord; break;
        case 233: result.opcode = PpcOpcode::kMultiplyLowDoubleword; break;
        case 75: result.opcode = PpcOpcode::kMultiplyHighWord; break;
        case 11: result.opcode = PpcOpcode::kMultiplyHighWordUnsigned; break;
        case 73: result.opcode = PpcOpcode::kMultiplyHighDoubleword; break;
        case 9: result.opcode = PpcOpcode::kMultiplyHighDoublewordUnsigned; break;
        case 491: result.opcode = PpcOpcode::kDivideWord; break;
        case 459: result.opcode = PpcOpcode::kDivideWordUnsigned; break;
        case 489: result.opcode = PpcOpcode::kDivideDoubleword; break;
        case 457: result.opcode = PpcOpcode::kDivideDoublewordUnsigned; break;
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
