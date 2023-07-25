package io.iohk.atala.prism.apollo.utils

import io.iohk.atala.prism.apollo.cryptoKit.CryptoKit

public actual class KMMEdPrivateKey(val raw: ByteArray = CryptoKit().Ed25519privateKey()) {

    @Throws(RuntimeException::class)
    actual fun sign(message: ByteArray): ByteArray {
        return CryptoKit().Ed25519sign(raw, message)
    }

    @Throws(RuntimeException::class)
    public fun publicKey(): KMMEdPublicKey {
        return KMMEdPublicKey(CryptoKit().Ed25519publicKey(raw))
    }
}
