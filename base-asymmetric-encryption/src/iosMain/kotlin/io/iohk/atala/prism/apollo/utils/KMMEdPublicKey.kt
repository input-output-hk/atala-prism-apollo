package io.iohk.atala.prism.apollo.utils

import io.iohk.atala.prism.apollo.cryptoKit.CryptoKit

public actual class KMMEdPublicKey(val raw: ByteArray) {

    @Throws(RuntimeException::class)
    actual fun verify(message: ByteArray, sig: ByteArray): Boolean {
        return CryptoKit().Ed25519verify(raw, message, sig)
    }
}
