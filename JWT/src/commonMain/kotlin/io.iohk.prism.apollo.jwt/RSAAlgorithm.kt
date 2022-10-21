package io.iohk.prism.apollo.jwt

import io.iohk.atala.prism.apollo.base64.base64UrlDecodedBytes
import io.iohk.atala.prism.apollo.base64.base64UrlEncoded

final class RSAAlgorithm(
    /**
     * PEM String representing the key
     */
    private val key: String,
    private val keyType: RSAKey.Type,
    private val algorithm: Algorithm,
    private val usePSS: Boolean = false
) : VerifierAlgorithm, SignerAlgorithm {
    val name: String = "RSA"

    override fun sign(header: String, claims: String): String {
        val unsignedJWT = "$header.$claims"
        val unsignedData = unsignedJWT.encodeToByteArray()
        val signature = sign(unsignedData)
        val signatureString = signature.base64UrlEncoded
        return "$header.$claims.$signatureString"
    }

    override fun verify(jwt: String): Boolean {
        val components = jwt.split(".")
        return if (components.size == 3) {
            val signature = components[2].base64UrlDecodedBytes
            val jwtData = (components[0] + "." + components[1]).encodeToByteArray()
            verify(signature, jwtData)
        } else {
            false
        }
    }

    @Throws(JWTError.InvalidPrivateKey::class)
    fun sign(data: ByteArray): ByteArray {
        when (keyType) {
            RSAKey.Type.PUBLIC_KEY -> throw JWTError.InvalidPrivateKey()
            RSAKey.Type.PRIVATE_KEY -> {
                return if (this.usePSS) {
                    when (this.algorithm) {
                        Algorithm.SHA256 -> RSAPlatform.signSHA256RSA(key, data)
                        Algorithm.SHA384 -> RSAPlatform.signSHA384RSA(key, data)
                        Algorithm.SHA512 -> RSAPlatform.signSHA512RSA(key, data)
                    }
                } else {
                    when (this.algorithm) {
                        Algorithm.SHA256 -> RSAPlatform.signSHA256RSAPSS(key, data)
                        Algorithm.SHA384 -> RSAPlatform.signSHA384RSAPSS(key, data)
                        Algorithm.SHA512 -> RSAPlatform.signSHA512RSAPSS(key, data)
                    }
                }
            }
        }
    }

    fun verify(signature: ByteArray, data: ByteArray): Boolean {
        return when (keyType) {
            RSAKey.Type.PUBLIC_KEY -> {
                if (this.usePSS) {
                    when (this.algorithm) {
                        Algorithm.SHA256 -> RSAPlatform.verifySignSHA256RSA(key, data, signature)
                        Algorithm.SHA384 -> RSAPlatform.verifySignSHA384RSA(key, data, signature)
                        Algorithm.SHA512 -> RSAPlatform.verifySignSHA512RSA(key, data, signature)
                    }
                } else {
                    when (this.algorithm) {
                        Algorithm.SHA256 -> RSAPlatform.verifySignSHA256RSAPSS(key, data, signature)
                        Algorithm.SHA384 -> RSAPlatform.verifySignSHA384RSAPSS(key, data, signature)
                        Algorithm.SHA512 -> RSAPlatform.verifySignSHA512RSAPSS(key, data, signature)
                    }
                }
            }
            RSAKey.Type.PRIVATE_KEY -> false
        }
    }

    /**
     * Available Digest algorithms
     */
    enum class Algorithm {
        /**
         * Secure Hash Algorithm SHA-2 256-bit
         */
        SHA256,

        /**
         * Secure Hash Algorithm SHA-2 384-bit
         */
        SHA384,

        /**
         * Secure Hash Algorithm SHA-2 512-bit
         */
        SHA512;

//        fun algorithmForSignature(): Int {
//            return when (this) {
//                SHA256 -> TODO() // iOS: rsaSignatureMessagePKCS1v15SHA256
//                SHA384 -> TODO() // iOS: rsaSignatureMessagePKCS1v15SHA384
//                SHA512 -> TODO() // iOS: rsaSignatureMessagePKCS1v15SHA512
//            }
//        }
//
//        fun algorithmForPssSignature(): Int {
//            return when (this) {
//                SHA256 -> TODO() // iOS: rsaSignatureMessagePSSSHA256
//                SHA384 -> TODO() // iOS: rsaSignatureMessagePSSSHA384
//                SHA512 -> TODO() // iOS: rsaSignatureMessagePSSSHA512
//            }
//        }
//
//        fun alogrithmForEncryption(): Int {
//            return when (this) {
//                SHA256 -> TODO() // iOS: rsaEncryptionOAEPSHA256AESGCM
//                SHA384 -> TODO() // iOS: rsaEncryptionOAEPSHA384AESGCM
//                SHA512 -> TODO() // iOS: rsaEncryptionOAEPSHA512AESGCM
//            }
//        }
    }
}
