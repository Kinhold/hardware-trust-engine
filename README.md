# Hardware Trust Engine Core

Zero-Knowledge Hardware Enclave Signature Anonymizer Core Protocol.

## Device Compilation Metrics

The following metrics were recorded during the initial build verification:

*   **Device**: Moto G (ARM architecture)
*   **Environment**: proot Ubuntu
*   **Compilation Time**: ~2m 39s (`cargo build --release`)
*   **Memory Footprint**: TBD (Measure with `time -v cargo build --release`)
*   **Minimum Supported Version**: Arkworks 0.5.x is the minimum supported version for mobile ARM.

## Technical Notes

*   Utilizes **arkworks** (Groth16, R1CS) for Zero-Knowledge proofs.
*   Implements non-native field constraints for P-256 signature verification.
*   Designed for seamless integration with mobile hardware enclaves via FFI.
