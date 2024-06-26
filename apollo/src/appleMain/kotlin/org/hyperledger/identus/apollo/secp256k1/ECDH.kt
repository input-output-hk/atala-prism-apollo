package org.hyperledger.identus.apollo.secp256k1

import fr.acinq.secp256k1.Secp256k1Native

/**
 * This class provides the functionality to compute an elliptic curve Diffie-Hellman secret.
 *
 * @constructor Creates an instance of the ECDH class.
 */
class ECDH {
    /**
     * Compute an elliptic curve Diffie-Hellman secret.
     */
    fun ecdh(privateKey: ByteArray, publicKey: ByteArray): ByteArray {
        require(privateKey.size == 32)
        require(publicKey.size == 33 || publicKey.size == 65)
        return Secp256k1Native.ecdh(privateKey, publicKey)
    }
}
