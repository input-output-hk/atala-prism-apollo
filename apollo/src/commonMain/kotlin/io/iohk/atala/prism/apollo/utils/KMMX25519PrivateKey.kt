package io.iohk.atala.prism.apollo.utils

/**
 * Definition of the KMMX25519PrivateKey functionality
 */
expect class KMMX25519PrivateKey {
    /**
     * Generates a public key from the given private key.
     *
     * @return The generated public key.
     */
    fun publicKey(): KMMX25519PublicKey
}
