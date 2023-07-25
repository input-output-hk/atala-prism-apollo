package io.iohk.atala.prism.apollo.utils

// import cocoapods.IOHKRSA.IOHKRSA
import platform.Security.SecKeyRef

actual final class KMMRSAKeyPair actual constructor(val privateKey: KMMRSAPrivateKey, val publicKey: KMMRSAPublicKey) {

    private constructor(nativePrivateKey: SecKeyRef, nativePublicKey: SecKeyRef) : this(KMMRSAPrivateKey(nativePrivateKey), KMMRSAPublicKey(nativePublicKey))

    actual companion object : RSAKeyPairGeneration {
//        override suspend fun generateRSAKeyPair(algorithm: RSAAsymmetricAlgorithm, keySize: Int): KMMRSAKeyPair {
//
// //            val pair = IOHKRSA.generateKeyPairWithKeySize(keySize.toLong())!!
// //            return KMMRSAKeyPair(pair.privateKey()!!, pair.publicKey()!!)
//        }
//
//        override suspend fun generateRSAKeyPairFrom(seed: ByteArray, algorithm: RSAAsymmetricAlgorithm, keySize: Int): KMMRSAKeyPair {
// //            val pair = IOHKRSA.generateKeyPairWithKeySize(keySize.toLong())!!
// //            return KMMRSAKeyPair(pair.privateKey()!!, pair.publicKey()!!)
//        }
    }
}
