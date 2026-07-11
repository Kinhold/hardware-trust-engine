
# justfile

# Define a variable for the Rust target directory
RUST_TARGET_DIR := target

# Define a variable for the Android bindings directory
ANDROID_BINDINGS_DIR := bindings/android

# Define a variable for the Swift bindings directory
SWIFT_BINDINGS_DIR := bindings/swift

# Default recipe
default:
    @echo "Run `just --list` for available commands."

# Build the Rust library
build-rust:
    cargo build

# Run Rust tests
test-rust:
    cargo test

# Build Android AAR
build-android-aar:
    cd {{ANDROID_BINDINGS_DIR}} && ./build_aar.sh

# Build Swift XCFramework
build-swift-xcframework:
    cd {{SWIFT_BINDINGS_DIR}} && ./build_xcframework.sh

# Recipe for simulated error injections (Defensive Failure Matrix)
# This is a placeholder and would require more sophisticated implementation
# to actually inject errors and verify system state recovery.
simulate-error-injection:
    @echo "Simulating error injections... (Placeholder)"
    @echo "- Passing corrupted TEE bytes"
    @echo "- Tampered ZK proofs"
    @echo "- Expired attestation nonces"
    @echo "- Sudden out-of-order finalize invocations"
    @echo "Verification of perfect system state-recovery would be implemented here."

# Clean all build artifacts
clean:
    cargo clean
    rm -rf {{ANDROID_BINDINGS_DIR}}/build
    rm -rf {{SWIFT_BINDINGS_DIR}}/build
    rm -rf {{RUST_TARGET_DIR}}
    
