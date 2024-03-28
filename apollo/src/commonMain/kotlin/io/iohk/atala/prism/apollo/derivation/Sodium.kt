package io.iohk.atala.prism.apollo.derivation

import com.ionspin.kotlin.bignum.integer.util.toBigEndianUByteArray
import com.ionspin.kotlin.crypto.box.Box
import com.ionspin.kotlin.crypto.keyexchange.KeyExchange
import org.kotlincrypto.macs.hmac.sha2.HmacSHA512
import kotlin.js.ExperimentalJsExport
import kotlin.js.JsExport

// this is just for testing, actual code needs to be in HDKey
// have been using HDKey companion functions to avoid breaking

@OptIn(ExperimentalJsExport::class)
@JsExport
data class Key(val key: ByteArray, val chainCode: ByteArray)

@OptIn(ExperimentalJsExport::class)
@JsExport
class Sodium {
    private val hardenedOffset = 0x80000000
    fun getMasterKeyFromSeed(seed: ByteArray): Key {
        val init = "ed25519 seed".encodeToByteArray()
        val hmac = HmacSHA512(init)
        hmac.update(seed)
        val result = hmac.doFinal()
        val key = result.copyOfRange(0, 32)
        val chainCode = result.copyOfRange(32, 64)

        return Key(key, chainCode)
    }

    @OptIn(ExperimentalUnsignedTypes::class)
    fun derive(seed: ByteArray, index: Int): Key {
        val masterKey = getMasterKeyFromSeed(seed)
        val offset = (index + hardenedOffset).toUInt()
        val bytes = offset.toBigEndianUByteArray().toByteArray()
        val data = byteArrayOf(0).plus(masterKey.key.plus(bytes))
        val hmac = HmacSHA512(masterKey.chainCode)
        val result = hmac.doFinal(data)
        val key = result.copyOfRange(0, 32)
        val chainCode = result.copyOfRange(32, 64)

        return Key(key, chainCode)
    }


    @OptIn(ExperimentalStdlibApi::class)
    fun keygen(seed: ByteArray): Key {
        // this KeyExchange.seedKeyPair might be usable for X25519
        // would need to be ported to HDKey
        val kkp = KeyExchange.seedKeypair(seed.toUByteArray())
        // no idea what Box is, just used it for testing to simulate another Key
        val bkp = Box.seedKeypair(seed.toUByteArray())
//        val skp = Signature.seedKeypair(seed.toUByteArray())

        val clientSessionKeyPair = KeyExchange.clientSessionKeys(
            bkp.publicKey,
            bkp.secretKey,
            kkp.publicKey
        )
        val serverSessionKeyPair = KeyExchange.serverSessionKeys(
            kkp.publicKey,
            kkp.secretKey,
            bkp.publicKey
        )

        val a = clientSessionKeyPair.sendKey.toHexString()
        val b = serverSessionKeyPair.receiveKey.toHexString()
        // matched should be true
        val matched = a == b

        return Key(kkp.secretKey.toByteArray(), kkp.publicKey.toByteArray())
    }

}