# Hardware Trust Engine Core

Pre-alpha Kinhold hardware trust engine package scaffold.

## Security status

**Do not use this crate to make security, identity, authorization, or payment
decisions.** It does not verify signatures, hardware-backed keys, certificate
chains, Android Key Attestation, SGX/SEV quotes, or zero-knowledge proofs in its
default configuration.

Finalizing an attestation only packages non-empty signature bytes with the exact
challenge-bound signing message. Every resulting envelope is explicitly marked
`not_performed` for signature verification. Callers must perform real
cryptographic verification against a validated attested key before trusting it.

TEE parser/verifier entry points fail closed with an unsupported-operation error;
they never report placeholder input as valid. The verifier registry is empty by
default and only dispatches implementations explicitly registered by the
embedding application.

## Implemented scaffold

- one-use prepared-attestation state consumed on finalization
- 256-bit challenges from the operating system CSPRNG
- domain-separated signing messages binding challenge, timestamp, length, and payload
- two-second expiration with clock-rollback rejection
- explicit unverified-signature status
- fail-closed verifier registry and TEE stubs
- opaque C handles, checked null/length inputs, caller-owned output buffers, and
  documented consume/free semantics
- Android-only JNI compilation

The C ABI is still pre-alpha: exported records use `repr(C)` and avoid Rust
containers, but no compatibility guarantee or generated header is provided yet.

## Building

The default Rust build is self-contained and targets Rust 1.83 or newer:

```sh
cargo test
cargo clippy --all-targets
```

The opt-in `barretenberg-ffi` feature declares a native
`barretenberg_verify_proof` symbol that the embedding application must supply
with the documented C ABI. It is intentionally excluded from default builds
and is not a bundled or audited proof verifier.

## Required before production or publication

1. implement signature verification and bind it to a validated hardware key
2. implement strict DER/X.509 parsing, chain validation, revocation/status
   policy, and Android attestation authorization-list checks
3. implement and audit SGX/SEV quote verification and measurement policy
4. integrate and audit a real proof verifier instead of relying on an unresolved
   host symbol
5. define and test versioned C headers plus Android/iOS ownership behavior
6. add platform integration, fuzzing, adversarial-parser, and cryptographic
   test vectors

The Cargo package is marked `publish = false` until those release blockers are
resolved.
