/**
 * @file        system/interpreter_guest_executor.h
 * @brief       Initial lightweight PowerPC interpreter backend
 */

#pragma once

#include <cstdint>

#include <rex/system/guest_executor.h>

namespace rex::runtime {

class InterpreterGuestExecutor final : public GuestExecutor {
 public:
  explicit InterpreterGuestExecutor(uint64_t instruction_limit = 10'000'000)
      : instruction_limit_(instruction_limit) {}

  GuestExecutionResult Execute(PPCContext& context, uint8_t* memory_base,
                               uint32_t guest_address) override;

 private:
  uint64_t instruction_limit_;
};

}  // namespace rex::runtime
