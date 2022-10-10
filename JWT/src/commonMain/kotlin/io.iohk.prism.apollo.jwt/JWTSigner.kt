package io.iohk.prism.apollo.jwt

import kotlin.jvm.JvmStatic

/**
 * JWTSigner will be used to sign the JWT `Header` and `Claims` and generate a signed JWT.
 */
class JWTSigner(
    /**
     * The name of the algorithm that will be set in the "alg" header
     */
    val name: String,
    private val signerAlgorithm: SignerAlgorithm
) {
    fun sign(header: String, claims: String) : String {
        return signerAlgorithm.sign(header, claims)
    }

    companion object {
        /**
         * Initialize a JWTSigner using the HMAC 256 bits algorithm and the provided privateKey.
         *
         * @param key The HMAC symmetric password data.
         */
        @JvmStatic
        fun hs256(key: ByteArray) : JWTSigner {
            return JWTSigner("HS256", HMACAlgorithm(key, HMACAlgorithm.HMACAlgo.SHA256))
        }

        /**
         * Initialize a JWTSigner using the HMAC 384 bits algorithm and the provided privateKey.
         *
         * @param key The HMAC symmetric password data.
         */
        @JvmStatic
        fun hs384(key: ByteArray) : JWTSigner {
            return JWTSigner("HS384", HMACAlgorithm(key, HMACAlgorithm.HMACAlgo.SHA384))
        }

        /**
         * Initialize a JWTSigner using the HMAC 512 bits algorithm and the provided privateKey.
         *
         * @param key The HMAC symmetric password data.
         */
        @JvmStatic
        fun hs512(key: ByteArray) : JWTSigner {
            return JWTSigner("HS512", HMACAlgorithm(key, HMACAlgorithm.HMACAlgo.SHA512))
        }
    }
}