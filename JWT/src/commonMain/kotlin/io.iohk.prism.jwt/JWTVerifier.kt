package io.iohk.prism.jwt

import kotlin.jvm.JvmStatic

/**
 * JWTVerifier will be used to verify the signature of a JWT is valid for the provided `Header` and `Claims`
 */
class JWTVerifier(
    private val verifierAlgorithm: VerifierAlgorithm
) {

    fun verify(jwt: String) : Boolean {
        return verifierAlgorithm.verify(jwt)
    }

    companion object {
        /**
         * Initialize a JWTVerifier that will always return true when verifying the JWT.
         * This is equivalent to using the "none" alg header.
         */
        @JvmStatic
        fun none() : JWTVerifier {
            return JWTVerifier(NoneAlgorithm())
        }

        /**
         * Initialize a JWTSigner using the HMAC 256 bits algorithm and the provided privateKey.
         * @param key The HMAC symmetric password data.
         */
        @JvmStatic
        fun hs256(key: ByteArray) : JWTVerifier {
            return JWTVerifier(HMACAlgorithm(key, HMACAlgorithm.HMACAlgo.SHA256))
        }

        /**
         * Initialize a JWTSigner using the HMAC 384 bits algorithm and the provided privateKey.
         * @param key The HMAC symmetric password data.
         */
        @JvmStatic
        fun hs384(key: ByteArray) : JWTVerifier {
            return JWTVerifier(HMACAlgorithm(key, HMACAlgorithm.HMACAlgo.SHA384))
        }

        /**
         * Initialize a JWTSigner using the HMAC 512 bits algorithm and the provided privateKey.
         * @param key The HMAC symmetric password data.
         */
        @JvmStatic
        fun hs512(key: ByteArray) : JWTVerifier {
            return JWTVerifier(HMACAlgorithm(key, HMACAlgorithm.HMACAlgo.SHA512))
        }

//        /**
//         * Initialize a JWTVerifier using the RSA 256 bits algorithm and the provided publicKey.
//         * @param publicKey The UTF8 encoded PEM public key, with a "BEGIN PUBLIC KEY" header.
//         */
//        @JvmStatic
//        fun rs256(publicKey: ByteArray) : JWTVerifier {
//
//        }
    }
}
