package io.iohk.atala.prism.apollo.derivation

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.toBigInteger
import io.iohk.atala.prism.apollo.utils.ECConfig
import io.iohk.atala.prism.apollo.utils.ECPrivateKeyDecodingException
import io.iohk.atala.prism.apollo.utils.KMMECSecp256k1PrivateKey
import org.kotlincrypto.macs.hmac.sha2.HmacSHA512
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport
import kotlin.js.JsName

/**
 * Represents and HDKey with its derive methods
 */
@OptIn(ExperimentalJsExport::class)
@JsExport
public class HDKey(
    val privateKey: ByteArray? = null,
    val publicKey: ByteArray? = null,
    val chainCode: ByteArray? = null,
    val depth: Int = 0,
    val childIndex: BigInteger = BigInteger(0),
) {

    @JsName("InitFromSeed")
    public constructor(seed: ByteArray, depth: Int, childIndex: BigInteger) : this(
        privateKey = sha512(key = "Bitcoin seed".encodeToByteArray(), input = seed).sliceArray(IntRange(0, 31)),
        chainCode = sha512("Bitcoin seed".encodeToByteArray(), seed).sliceArray(32 until seed.size),
        depth = depth,
        childIndex = childIndex
    ) {
        require(seed.size == 64) {
            "Seed expected byte length to be ${ECConfig.PRIVATE_KEY_BYTE_SIZE}"
        }
    }

    /**
     * Method to derive an HDKey by a path
     *
     * @param path value used to derive a key
     */
    public fun derive(path: String): HDKey {
        if (!path.matches(Regex("^[mM].*"))) {
            throw Error("Path must start with \"m\" or \"M\"")
        }
        if (Regex("^[mM]'?$").matches(path)) {
            return this
        }
        val parts = path.replace(Regex("^[mM]'?/"), "").split("/")
        var child = this
        for (c in parts) {
            val m = Regex("^(\\d+)('?)$").find(c)?.groupValues
            if (m == null || m.size != 3) {
                throw Error("Invalid child index: $c")
            }
            val idx = m[1].toBigInteger()
            if (idx >= HARDENED_OFFSET) {
                throw Error("Invalid index")
            }
            val finalIdx = if (m[2] == "'") idx + HARDENED_OFFSET else idx
            child = child.deriveChild(finalIdx)
        }
        return child
    }

    /**
     * Method to derive an HDKey child by index
     *
     * @param index value used to derive a key
     */
    public fun deriveChild(index: BigInteger): HDKey {
        if (chainCode == null) {
            throw Exception("No chainCode set")
        }

        val data = if (index >= HARDENED_OFFSET) {
            val priv = privateKey ?: throw Error("Could not derive hardened child key")
            byteArrayOf(0) + priv + index.toByteArray()
        } else {
            throw Exception("Not supported")
        }

        val I = sha512(chainCode, data)
        val childTweak = I.sliceArray(IntRange(0, 31))
        val newChainCode = I.sliceArray(32 until I.size)

        if (!isValidPrivateKey(childTweak)) {
            throw ECPrivateKeyDecodingException("Expected encoded byte length to be ${ECConfig.PRIVATE_KEY_BYTE_SIZE}, but got ${data.size}")
        }

        val opt = HDKeyOptions(
            versions = Pair(BITCOIN_VERSIONS_PRIVATE, BITCOIN_VERSIONS_PUBLIC),
            chainCode = newChainCode,
            depth = depth + 1,
            parentFingerprint = null,
            index = index
        )

        return try {
            opt.privateKey = KMMECSecp256k1PrivateKey.tweak(privateKey, childTweak).raw
            return HDKey(
                privateKey = opt.privateKey,
                chainCode = opt.chainCode,
                depth = opt.depth,
                childIndex = opt.index
            )
        } catch (err: Error) {
            this.deriveChild(index + 1)
        }
    }

    public fun getKMMSecp256k1PrivateKey(): KMMECSecp256k1PrivateKey {
        privateKey?.let {
            return KMMECSecp256k1PrivateKey.secp256k1FromByteArray(privateKey)
        } ?: throw Exception("Private key not available")
    }

    private fun isValidPrivateKey(data: ByteArray): Boolean {
        return (data.size == ECConfig.PRIVATE_KEY_BYTE_SIZE)
    }

    companion object {
        const val HARDENED_OFFSET = 2147483648
        const val BITCOIN_VERSIONS_PRIVATE = 0x0488ade4
        const val BITCOIN_VERSIONS_PUBLIC = 0x0488b21e
        const val FINGERPRINT = 0
        const val MASTER_SECRET = "Atala Prism"

        fun sha512(key: ByteArray, input: ByteArray): ByteArray {
            val sha512 = HmacSHA512(key)
            sha512.update(input)
            return sha512.doFinal()
        }
    }
}
