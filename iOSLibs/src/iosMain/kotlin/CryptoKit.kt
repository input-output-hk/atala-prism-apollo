package io.iohk.atala.prism.apollo.cryptoKit

import cocoapods.IOHKCryptoKit.Ed25519
import cocoapods.IOHKCryptoKit.X25519
import io.iohk.atala.prism.apollo.utils.toByteArray
import io.iohk.atala.prism.apollo.utils.toNSData
import kotlinx.cinterop.ObjCObjectVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import platform.Foundation.NSError

class CryptoKit {
    fun Ed25519privateKey(): ByteArray {
        return Ed25519.createPrivateKey().toByteArray()
    }

    @Throws(RuntimeException::class)
    fun Ed25519sign(raw: ByteArray, message: ByteArray): ByteArray {
        memScoped {
            val errorRef = alloc<ObjCObjectVar<NSError?>>()
            val result = Ed25519.signWithPrivateKey(raw.toNSData(), message.toNSData(), errorRef.ptr)
            errorRef.value?.let { throw RuntimeException(it.localizedDescription()) }
            return result?.toByteArray() ?: throw RuntimeException("Null result")
        }
    }

    @Throws(RuntimeException::class)
    fun Ed25519publicKey(privateKey: ByteArray): ByteArray {
        memScoped {
            val errorRef = alloc<ObjCObjectVar<NSError?>>()
            val result = Ed25519.publicKeyWithPrivateKey(privateKey.toNSData(), errorRef.ptr)
            errorRef.value?.let { throw RuntimeException(it.localizedDescription()) }
            return result?.toByteArray() ?: throw RuntimeException("Null result")
        }
    }

    @Throws(RuntimeException::class)
    fun Ed25519verify(publicKey: ByteArray, message: ByteArray, sig: ByteArray): Boolean {
        memScoped {
            val errorRef = alloc<ObjCObjectVar<NSError?>>()
            val result = Ed25519.verifyWithPublicKey(publicKey.toNSData(), sig.toNSData(), message.toNSData(), errorRef.ptr)
            errorRef.value?.let { throw RuntimeException(it.localizedDescription()) }
            return result?.boolValue ?: throw RuntimeException("Null result")
        }
    }

    fun X25519PrivateKey(): ByteArray {
        return X25519.createPrivateKey().toByteArray()
    }

    @Throws(RuntimeException::class)
    fun X25519publicKey(privateKey: ByteArray): ByteArray {
        memScoped {
            val errorRef = alloc<ObjCObjectVar<NSError?>>()
            val result = X25519.publicKeyWithPrivateKey(privateKey.toNSData(), errorRef.ptr)
            errorRef.value?.let { throw RuntimeException(it.localizedDescription()) }
            return result?.toByteArray() ?: throw RuntimeException("Null result")
        }
    }
}
