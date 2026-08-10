/**
 * @file        system/ppc_decoder.h
 * @brief       Lightweight runtime PowerPC instruction decoder
 */

#pragma once

#include <cstdint>

namespace rex::runtime {

enum class PpcOpcode : uint8_t {
  kUnknown,
  kAddImmediate,
  kAddImmediateShifted,
  kOrImmediate,
  kXorImmediate,
  kLoadWord,
  kLoadWordUpdate,
  kLoadWordIndexed,
  kLoadByte,
  kLoadByteUpdate,
  kLoadByteIndexed,
  kLoadHalf,
  kLoadHalfUpdate,
  kLoadHalfIndexed,
  kLoadHalfSigned,
  kLoadHalfSignedIndexed,
  kStoreWord,
  kStoreWordUpdate,
  kStoreWordIndexed,
  kStoreByte,
  kStoreByteUpdate,
  kStoreByteIndexed,
  kStoreHalf,
  kStoreHalfUpdate,
  kStoreHalfIndexed,
  kBranch,
  kBranchConditional,
  kBranchConditionalToLinkRegister,
  kCompareImmediate,
  kCompareLogicalImmediate,
  kOr,
  kXor,
  kAnd,
  kMoveFromSpr,
  kMoveToSpr,
  kAdd,
  kSubtractFrom,
  kNegate,
};

struct DecodedPpcInstruction {
  PpcOpcode opcode = PpcOpcode::kUnknown;
  uint32_t raw = 0;
  uint8_t rt = 0;
  uint8_t ra = 0;
  uint8_t bo = 0;
  uint8_t bi = 0;
  uint8_t rb = 0;
  uint8_t cr_field = 0;
  uint16_t spr = 0;
  int32_t immediate = 0;
  bool is_64_bit = false;
  bool absolute = false;
  bool link = false;
  bool record = false;
};

DecodedPpcInstruction DecodePpcInstruction(uint32_t raw);

}  // namespace rex::runtime
