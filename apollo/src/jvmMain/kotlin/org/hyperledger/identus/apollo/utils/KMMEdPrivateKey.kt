package org.hyperledger.identus.apollo.utils

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.ByteArrayInputStream

/**
 * Represents a private key for the KMMEd cryptographic system.
 *
 * @property raw The raw byte array representation of the private key.
 */
actual class KMMEdPrivateKey(val raw: ByteArray) {
    /**
     * Generates a public key corresponding to this private key.
     *
     * @return The public key as a [KMMEdPublicKey] object.
     */
    fun publicKey(): KMMEdPublicKey {
        val private = Ed25519PrivateKeyParameters(raw, 0)
        val public = private.generatePublicKey()
        return KMMEdPublicKey(public.encoded)
    }

    /**
     * Signs a message using the Ed25519 algorithm.
     *
     * @param message The message to be signed.
     * @return The generated signature as a byte array.
     */
    actual fun sign(message: ByteArray): ByteArray {
        val privateKeyParameters = Ed25519PrivateKeyParameters(ByteArrayInputStream(raw))
        val signer = Ed25519Signer()
        signer.init(true, privateKeyParameters)
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }

    /**
     * Method convert an ed25519 private key to a x25519 private key
     *
     * @return KMMX25519PrivateKey private key
     */
    actual fun x25519PrivateKey(): KMMX25519PrivateKey {
        val rawX25519Prv = convertSecretKeyToX25519(this.raw)
        return KMMX25519PrivateKey(rawX25519Prv)
    }
}
