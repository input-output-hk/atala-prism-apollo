package io.iohk.atala.prism.apollo.utils

import io.iohk.atala.prism.apollo.cryptoKit.CryptoKit

actual class KMMX25519PrivateKey {
    public val raw: ByteArray

    constructor(raw: ByteArray) {
        this.raw = raw
    }

    constructor() {
        this.raw = CryptoKit().X25519PrivateKey()
    }

    @Throws(RuntimeException::class)
    public fun publicKey(): KMMX25519PublicKey {
        return KMMX25519PublicKey(CryptoKit().X25519publicKey(raw))
    }
}
