/**
 * @file        system/guest_executor.h
 * @brief       Common execution contract for guest PowerPC code
 */

#pragma once

#include <cstdint>

#include <rex/ppc/context.h>

namespace rex::runtime {

enum class GuestExecutionStatus : uint8_t {
  kSuccess,
  kUnmappedAddress,
  kFault,
  kStopped,
};

struct GuestExecutionResult {
  GuestExecutionStatus status = GuestExecutionStatus::kFault;
  uint32_t guest_address = 0;

  [[nodiscard]] bool succeeded() const { return status == GuestExecutionStatus::kSuccess; }

  static GuestExecutionResult Success(uint32_t address) {
    return {GuestExecutionStatus::kSuccess, address};
  }
  static GuestExecutionResult Unmapped(uint32_t address) {
    return {GuestExecutionStatus::kUnmappedAddress, address};
  }
};

/// Backend-independent contract for executing guest code. Implementations may
/// dispatch ahead-of-time compiled functions, interpret PPC instructions, or
/// execute dynamically compiled blocks.
class GuestExecutor {
 public:
  virtual ~GuestExecutor() = default;

  virtual GuestExecutionResult Execute(PPCContext& context, uint8_t* memory_base,
                                       uint32_t guest_address) = 0;
  virtual PPCFunc* LookupFunction(uint32_t) const { return nullptr; }
  virtual void RegisterFunction(uint32_t, PPCFunc*) {}
};

}  // namespace rex::runtime
