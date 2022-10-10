package io.iohk.prism.apollo.jwt

import io.iohk.atala.prism.apollo.base64.base64UrlDecodedBytes
import io.iohk.atala.prism.apollo.base64.base64UrlEncoded
import io.iohk.prism.apollo.hashing.SHA256
import io.iohk.prism.apollo.hashing.SHA384
import io.iohk.prism.apollo.hashing.SHA512
import io.iohk.prism.apollo.hashing.internal.Digest

class HMACAlgorithm(
    private val key: ByteArray,
    private val algo: HMACAlgo
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
            HMACAlgo.SHA256 -> {
                SHA256().createHmac(key)
            }
            HMACAlgo.SHA384 -> {
                SHA384().createHmac(key)
            }
            HMACAlgo.SHA512 -> {
                SHA512().createHmac(key)
            }
        }
        return hash.digest(data)
    }

    fun verify(signature: ByteArray, data: ByteArray) : Boolean {
        val expectedHMAC = sign(data)
        return expectedHMAC.contentEquals(signature)
    }

    final enum class HMACAlgo {
        SHA256, SHA384, SHA512;
    }
}
