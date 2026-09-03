add_library(eos_linux_security STATIC
    src/linux_security.c
)

target_include_directories(eos_linux_security PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# For EOS_ERROR. Same resolution as #108 took for eos_ota: report through the
# tree's logger rather than fprintf(stderr). No cycle -- eos_core does not
# depend on eos_linux_security.
target_link_libraries(eos_linux_security PUBLIC eos_core)

target_compile_options(eos_linux_security PRIVATE
    $<$<C_COMPILER_ID:GNU>:-Wall -Wextra -Wpedantic>
    $<$<C_COMPILER_ID:Clang>:-Wall -Wextra -Wpedantic>
    $<$<C_COMPILER_ID:MSVC>:/W4>
)
