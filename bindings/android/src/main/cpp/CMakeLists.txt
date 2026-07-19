
cmake_minimum_required(VERSION 3.10.2)

project("hardware_trust_engine")

add_library(hardware_trust_engine SHARED
    src/main/cpp/HteBridge.cpp # Placeholder for C++ wrapper if needed
)

# Find and link the Rust static library
# Assuming the Rust library is built as a static library named `libhardware_trust_engine.a`
# and located in a known path relative to this CMakeLists.txt
# For simplicity, we'll assume it's in a pre-built location or handled by Gradle

# In a real scenario, you would integrate with `cargo-ndk` or similar for proper Rust-Android integration
# For now, we'll just define the library and let Gradle handle the Rust part.

# Example of how to link a pre-built Rust library (conceptual)
# add_library(rust_hardware_trust_engine STATIC IMPORTED)
# set_target_properties(rust_hardware_trust_engine PROPERTIES
#     IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../../../rust/target/aarch64-linux-android/release/libhardware_trust_engine.a
# )
# target_link_libraries(hardware_trust_engine rust_hardware_trust_engine)

# Set aggressive release flags
if(CMAKE_BUILD_TYPE MATCHES "Release")
    target_compile_options(hardware_trust_engine PRIVATE
        -O3
        -flto
        -fvisibility=hidden
    )
    target_link_options(hardware_trust_engine PRIVATE
        -flto
    )
endif()

# Link system libraries
target_link_libraries(hardware_trust_engine
    android
    log
)
