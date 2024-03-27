package io.iohk.atala.prism.apollo.utils

import io.iohk.atala.prism.apollo.base64.base64UrlEncoded
import io.iohk.atala.prism.apollo.utils.external.KeyPair
import io.iohk.atala.prism.apollo.utils.external.generateKeyPairFromSeed
import node.buffer.Buffer

/**
 * Represents a private key for the X25519 elliptic curve encryption algorithm.
 *
 * @property raw The binary representation of the private key.
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
actual class KMMX25519PrivateKey(bytes: ByteArray) {
    val raw: Buffer

    init {
        raw = Curve25519Parser.parseRaw(bytes)
    }

    /**
     * Base64 url encodes the raw value
     * @return Buffer
     */
    fun getEncoded(): Buffer {
        return Buffer.from(raw.toByteArray().base64UrlEncoded)
    }

    /**
     * PublicKey associated with this PrivateKey
     * @return KMMX25519PublicKey
     */
    actual fun publicKey(): KMMX25519PublicKey {
        val publicBytes = getInstance().publicKey.buffer.toByteArray()

        return KMMX25519PublicKey(publicBytes)
    }

    /**
     * Retrieves an instance of `KeyPair` by generating it from the given raw private key.
     *
     * @return The generated `KeyPair` object containing the public key and secret key.
     */
    private fun getInstance(): KeyPair {
        return generateKeyPairFromSeed(raw)
    }
}
