package io.iohk.atala.prism.apollo.utils

import org.bouncycastle.crypto.params.X25519PrivateKeyParameters

/**
 * Represents a private key for the X25519 elliptic curve encryption algorithm.
 *
 * @property raw The binary representation of the private key.
 */
actual class KMMX25519PrivateKey(val raw: ByteArray) {
    /**
     * Generates a public key from the private key using the X25519 elliptic curve encryption algorithm.
     *
     * @return A `KMMX25519PublicKey` object representing the generated public key.
     */
    actual fun publicKey(): KMMX25519PublicKey {
        val private = X25519PrivateKeyParameters(raw, 0)
        val public = private.generatePublicKey()
        return KMMX25519PublicKey(public.encoded)
    }
}
