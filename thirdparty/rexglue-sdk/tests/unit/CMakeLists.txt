# Unit Tests for ReXGlue core components

add_executable(unit_tests
    memory/heap_allocation_test.cpp
    kernel/object_table_test.cpp
    core/cvar_test.cpp
    core/fiber_test.cpp
    core/sha256_test.cpp
    core/stream_test.cpp
    core/byte_order_test.cpp
    core/chrono_test.cpp
    codegen/config_test.cpp
    codegen/template_registry_test.cpp
)

target_include_directories(unit_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)

target_link_libraries(unit_tests PRIVATE
    rexcore
    rexcodegen
    rexkernel
    Catch2::Catch2WithMain
)

set_target_properties(unit_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/bin
)

# Discover tests
include(Catch)
catch_discover_tests(unit_tests
    TEST_PREFIX "unit."
    PROPERTIES
        LABELS "unit"
        TIMEOUT 60
)

# Keep execution-contract tests independent of the kernel/system static-library
# cycle so they can validate the adapter in isolation.
add_executable(executor_unit_tests
    system/aot_guest_executor_test.cpp
    system/interpreter_guest_executor_test.cpp
    system/xex_revision_test.cpp
    ${PROJECT_SOURCE_DIR}/src/system/aot_guest_executor.cpp
    ${PROJECT_SOURCE_DIR}/src/system/interpreter_guest_executor.cpp
    ${PROJECT_SOURCE_DIR}/src/system/ppc_decoder.cpp
    ${PROJECT_SOURCE_DIR}/src/system/xex_revision.cpp
)
target_include_directories(executor_unit_tests PRIVATE
    ${PROJECT_SOURCE_DIR}/include
)
target_link_libraries(executor_unit_tests PRIVATE
    rexcore
    Catch2::Catch2WithMain
)
set_target_properties(executor_unit_tests PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/tests/bin
)
catch_discover_tests(executor_unit_tests
    TEST_PREFIX "unit.executor."
    PROPERTIES
        LABELS "unit;executor"
        TIMEOUT 60
)
