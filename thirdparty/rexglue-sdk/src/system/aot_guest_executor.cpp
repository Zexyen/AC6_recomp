/**
 * @file        system/aot_guest_executor.cpp
 * @brief       GuestExecutor adapter for existing AOT-recompiled functions
 */

#include <mutex>

#include <rex/system/aot_guest_executor.h>

namespace rex::runtime {

GuestExecutionResult AotGuestExecutor::Execute(PPCContext& context, uint8_t* memory_base,
                                               uint32_t guest_address) {
  PPCFunc* function = LookupFunction(guest_address);
  if (!function) {
    return GuestExecutionResult::Unmapped(guest_address);
  }

  function(context, memory_base);
  return GuestExecutionResult::Success(guest_address);
}

PPCFunc* AotGuestExecutor::LookupFunction(uint32_t guest_address) const {
  std::shared_lock lock(functions_mutex_);
  auto it = functions_.find(guest_address);
  return it == functions_.end() ? nullptr : it->second;
}

void AotGuestExecutor::RegisterFunction(uint32_t guest_address, PPCFunc* function) {
  std::unique_lock lock(functions_mutex_);
  if (function) {
    functions_[guest_address] = function;
  } else {
    functions_.erase(guest_address);
  }
}

}  // namespace rex::runtime
