package io.iohk.atala.prism.apollo.utils

import kotlinx.cinterop.ExperimentalForeignApi
import swift.cryptoKit.X25519

/**
 * Represents a private key for the X25519 elliptic curve encryption algorithm.
 *
 * @property raw The binary representation of the private key.
 */
@OptIn(ExperimentalForeignApi::class)
actual class KMMX25519PrivateKey(val raw: ByteArray) {
    /**
     * Constructs a new instance of [KMMX25519PrivateKey].
     *
     * @throws RuntimeException if the result of [X25519.createPrivateKey] is null.
     */
    @Throws(RuntimeException::class)
    public constructor() : this(X25519.createPrivateKey().success()?.toByteArray() ?: throw RuntimeException("Null result"))

    /**
     * Generates the public key corresponding to a private key using the X25519 elliptic curve encryption algorithm.
     *
     * @return The generated public key.
     * @throws RuntimeException if there is an error generating the public key.
     */
    @Throws(RuntimeException::class)
    public actual fun publicKey(): KMMX25519PublicKey {
        val result = X25519.publicKeyWithPrivateKey(raw.toNSData())
        result.failure()?.let { throw RuntimeException(it.localizedDescription()) }
        val publicRaw = result.success()?.toByteArray() ?: throw RuntimeException("Null result")
        return KMMX25519PublicKey(publicRaw)
    }
}
