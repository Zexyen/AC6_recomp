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
    case 36:
      result.opcode = PpcOpcode::kStoreWord;
      result.immediate = SignExtend(raw & 0xFFFF, 16);
      break;
    case 18:
      result.opcode = PpcOpcode::kBranch;
      result.immediate = SignExtend(raw & 0x03FFFFFC, 26);
      result.absolute = (raw & 2) != 0;
      result.link = (raw & 1) != 0;
      break;
    case 19:
      if (((raw >> 1) & 0x3FF) == 16) {
        result.opcode = PpcOpcode::kBranchConditionalToLinkRegister;
        result.bo = static_cast<uint8_t>((raw >> 21) & 31);
        result.bi = static_cast<uint8_t>((raw >> 16) & 31);
        result.link = (raw & 1) != 0;
      }
      break;
    default:
      break;
  }
  return result;
}

}  // namespace rex::runtime
