package io.iohk.prism.jwt

import io.iohk.atala.prism.apollo.base64.base64UrlDecoded
import io.iohk.atala.prism.apollo.base64.base64UrlDecodedBytes
import io.iohk.atala.prism.apollo.base64.base64UrlEncoded
import io.iohk.prism.apollo.hashing.SHA256
import io.iohk.prism.apollo.hashing.SHA384
import io.iohk.prism.apollo.hashing.SHA512
import io.iohk.prism.apollo.hashing.internal.Digest
import kotlin.jvm.JvmStatic

class HMACAlgorithm(
    private val key: ByteArray,
    private val algo: JWTHMACAlgo
): SignerAlgorithm, VerifierAlgorithm {
    val name: String = "HMAC"

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

    fun sign(data: ByteArray) : ByteArray {
        val hash: Digest = when (algo) {
            JWTHMACAlgo.HS256 -> {
                SHA256().createHmac(key)
            }
            JWTHMACAlgo.HS384 -> {
                SHA384().createHmac(key)
            }
            JWTHMACAlgo.HS512 -> {
                SHA512().createHmac(key)
            }
        }
        return hash.digest(data)
    }

    fun verify(signature: ByteArray, data: ByteArray) : Boolean {
        val expectedHMAC = sign(data)
        return expectedHMAC.contentEquals(signature)
    }

    final enum class JWTHMACAlgo(val algo: String) {
        HS256("HS256"),
        HS384("HS384"),
        HS512("HS512");

        companion object {
            @JvmStatic
            fun exist(algo: String): Boolean {
                for (element in JWTHMACAlgo.values()) {
                    if (element.algo == algo) {
                        return true
                    }
                }
                return false
            }
        }
    }
}