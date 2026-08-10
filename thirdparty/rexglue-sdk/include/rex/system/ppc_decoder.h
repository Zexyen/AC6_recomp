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
  kStoreWord,
  kBranch,
  kBranchConditionalToLinkRegister,
};

struct DecodedPpcInstruction {
  PpcOpcode opcode = PpcOpcode::kUnknown;
  uint32_t raw = 0;
  uint8_t rt = 0;
  uint8_t ra = 0;
  uint8_t bo = 0;
  uint8_t bi = 0;
  int32_t immediate = 0;
  bool absolute = false;
  bool link = false;
};

DecodedPpcInstruction DecodePpcInstruction(uint32_t raw);

}  // namespace rex::runtime
