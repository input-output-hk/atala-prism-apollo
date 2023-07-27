package io.iohk.atala.prism.apollo.utils

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.security.KeyPair
import java.security.KeyPairGenerator

actual class KMMEdKeyPair actual constructor(actual val privateKey: KMMEdPrivateKey, actual val publicKey: KMMEdPublicKey) {
    actual companion object : Ed25519KeyPairGeneration {
        override fun generateKeyPair(): KMMEdKeyPair {
            val provider = BouncyCastleProvider()
            val generator = KeyPairGenerator.getInstance("Ed25519", provider)
            val javaKeyPair: KeyPair = generator.generateKeyPair()
            return KMMEdKeyPair(
                KMMEdPrivateKey(javaKeyPair.private.encoded),
                KMMEdPublicKey(javaKeyPair.public.encoded)
            )
        }
    }

    actual fun sign(message: ByteArray): ByteArray {
        return privateKey.sign(message)
    }

    actual fun verify(message: ByteArray, sig: ByteArray): Boolean {
        return publicKey.verify(message, sig)
    }
}