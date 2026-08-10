/**
 * @file        system/aot_guest_executor.h
 * @brief       GuestExecutor adapter for existing AOT-recompiled functions
 */

#pragma once

#include <shared_mutex>
#include <unordered_map>

#include <rex/system/guest_executor.h>

namespace rex::runtime {

class AotGuestExecutor final : public GuestExecutor {
 public:
  GuestExecutionResult Execute(PPCContext& context, uint8_t* memory_base,
                               uint32_t guest_address) override;
  PPCFunc* LookupFunction(uint32_t guest_address) const override;
  void RegisterFunction(uint32_t guest_address, PPCFunc* function) override;

 private:
  mutable std::shared_mutex functions_mutex_;
  std::unordered_map<uint32_t, PPCFunc*> functions_;
};

}  // namespace rex::runtime
