
import Foundation
import LocalAuthentication

public enum SecureEnclaveAttestorError: Error {
    case attestationFailed(String)
    case secureEnclaveError(String)
    case invalidInput
}

public class SecureEnclaveAttestor {

    private let serviceName = "com.genspark.hte.SecureEnclaveAttestor"

    public init() {}

    public func preparePrivateAttestation(payload: Data) throws -> (nonce: UInt16, timestampMs: UInt64, preparedAttestationPtr: UnsafeMutableRawPointer) {
        var nonce: UInt16 = 0
        var timestampMs: UInt64 = 0

        let preparedAttestationPtr = payload.withUnsafeBytes { (payloadBuffer: UnsafeRawBufferPointer) -> UnsafeMutableRawPointer in
            return hte_prepare_private_attestation(
                payloadBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                payloadBuffer.count,
                &nonce,
                &timestampMs
            )
        }

        if preparedAttestationPtr == nil {
            throw SecureEnclaveAttestorError.attestationFailed("Failed to prepare attestation in Rust core.")
        }

        return (nonce, timestampMs, preparedAttestationPtr)
    }

    public func finalizePrivateAttestation(
        preparedAttestationPtr: UnsafeMutableRawPointer,
        signedData: Data,
        signature: Data,
        nonce: UInt16,
        timestampMs: UInt64
    ) throws -> AttestationEnvelope {

        var envelope = AttestationEnvelope(
            signed_data: UnsafeMutablePointer<UInt8>.allocate(capacity: 0),
            signed_data_len: 0,
            signature: UnsafeMutablePointer<UInt8>.allocate(capacity: 0),
            signature_len: 0,
            nonce: 0,
            timestamp_ms: 0
        )

        let success = signedData.withUnsafeBytes { (signedDataBuffer: UnsafeRawBufferPointer) -> Bool in
            return signature.withUnsafeBytes { (signatureBuffer: UnsafeRawBufferPointer) -> Bool in
                return hte_finalize_private_attestation(
                    preparedAttestationPtr,
                    signedDataBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    signedDataBuffer.count,
                    signatureBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    signatureBuffer.count,
                    &envelope
                )
            }
        }

        if !success {
            throw SecureEnclaveAttestorError.attestationFailed("Failed to finalize attestation in Rust core.")
        }

        // Create a Swift Data object from the C-allocated buffer
        let finalSignedData = Data(bytes: envelope.signed_data, count: Int(envelope.signed_data_len))
        let finalSignature = Data(bytes: envelope.signature, count: Int(envelope.signature_len))

        // Free the C-allocated memory for the envelope fields
        hte_free_attestation_envelope(&envelope)

        return AttestationEnvelope(
            signed_data: finalSignedData,
            signature: finalSignature,
            nonce: envelope.nonce,
            timestamp_ms: envelope.timestamp_ms
        )
    }

    public func signWithSecureEnclave(data: Data, prompt: String) throws -> Data {
        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) else {
            throw SecureEnclaveAttestorError.secureEnclaveError(error?.localizedDescription ?? "Biometric authentication not available.")
        }

        let success = context.evaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics,
            localizedReason: prompt,
            reply: { (success, error) in
                // This is an async callback, for simplicity we'll assume synchronous behavior for now
                // In a real app, this would require a completion handler pattern.
            }
        )

        if !success {
            throw SecureEnclaveAttestorError.secureEnclaveError(error?.localizedDescription ?? "User authentication failed.")
        }

        // Placeholder for actual Secure Enclave signing logic
        // This would involve using `SecKeyCreateSignature` with a hardware-backed key.
        // For now, we return a dummy signature.
        return Data("dummy_secure_enclave_signature".utf8)
    }

    deinit {
        // Ensure any remaining prepared attestation pointers are freed if not finalized
        // This is a simplification; a robust solution would track active pointers.
    }
}

// Define a Swift struct that mirrors the Rust AttestationEnvelope for FFI
public struct AttestationEnvelope {
    var signed_data: UnsafeMutablePointer<UInt8>
    var signed_data_len: UInt
    var signature: UnsafeMutablePointer<UInt8>
    var signature_len: UInt
    var nonce: UInt16
    var timestamp_ms: UInt64
}

// C-FFI function declarations (from hardware_trust_engine.h)
@_silgen_name("hte_prepare_private_attestation")
func hte_prepare_private_attestation(
    _ payload_ptr: UnsafePointer<UInt8>?,
    _ payload_len: Int,
    _ nonce_out: UnsafeMutablePointer<UInt16>,
    _ timestamp_ms_out: UnsafeMutablePointer<UInt64>
) -> UnsafeMutableRawPointer

@_silgen_name("hte_finalize_private_attestation")
func hte_finalize_private_attestation(
    _ prepared_attestation_ptr: UnsafeMutableRawPointer?,
    _ signed_data_ptr: UnsafePointer<UInt8>?,
    _ signed_data_len: Int,
    _ signature_ptr: UnsafePointer<UInt8>?,
    _ signature_len: Int,
    _ envelope_out: UnsafeMutablePointer<AttestationEnvelope>
) -> Bool

@_silgen_name("hte_free_prepared_attestation")
func hte_free_prepared_attestation(_ prepared_attestation_ptr: UnsafeMutableRawPointer?)

@_silgen_name("hte_free_attestation_envelope")
func hte_free_attestation_envelope(_ envelope_ptr: UnsafeMutablePointer<AttestationEnvelope>)
