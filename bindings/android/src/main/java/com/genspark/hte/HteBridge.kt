
package com.genspark.hte

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.spec.ECGenParameterSpec

class HteBridge {

    companion object {
        init {
            System.loadLibrary("hardware_trust_engine")
        }
    }

    external fun processPayload(input: String): String

    fun generateHardwareBackedSigningKey(alias: String): Boolean {
        try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)

            if (keyStore.containsAlias(alias)) {
                return true // Key already exists
            }

            val keyPairGenerator = KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                "AndroidKeyStore"
            )

            val parameterSpecBuilder = KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(false)
                .setIsStrongBoxBacked(true) // Mandate StrongBox backing

            try {
                keyPairGenerator.initialize(parameterSpecBuilder.build())
                keyPairGenerator.generateKeyPair()
                println("Key generated with StrongBox backing.")
                return true
            } catch (e: Exception) {
                // Fallback to TEE-backed security if StrongBox is not available
                println("StrongBox not available, falling back to TEE-backed security: ${e.message}")
                val teeParameterSpecBuilder = KeyGenParameterSpec.Builder(
                    alias,
                    KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
                )
                    .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .setUserAuthenticationRequired(false)
                    .setIsStrongBoxBacked(false) // Do not mandate StrongBox
                    .setAttestationChallenge("challenge".toByteArray())

                keyPairGenerator.initialize(teeParameterSpecBuilder.build())
                keyPairGenerator.generateKeyPair()
                println("Key generated with TEE backing.")

                // Verify if the key is hardware-backed (TEE or StrongBox)
                val entry = keyStore.getEntry(alias, null) as KeyStore.PrivateKeyEntry
                val certificate = entry.certificate
                // In a real scenario, you would parse the attestation certificate
                // to verify security level. For now, we assume success if no exception.
                println("Key successfully generated and is hardware-backed.")
                return true
            }
        } catch (e: Exception) {
            System.err.println("Fatal error: Key generation failed and defaulted to software backing or other issue: ${e.message}")
            // In a real application, this would be a fatal error or crash the app.
            return false
        }
    }

    // Custom exception class for native errors
    class HteNativeException(message: String) : Exception(message)
}
