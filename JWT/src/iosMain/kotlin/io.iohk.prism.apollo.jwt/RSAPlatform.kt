package io.iohk.prism.apollo.jwt

import cocoapods.IOHKCrypto.*
import io.iohk.atala.prism.apollo.base64.base64Decoded
import kotlinx.cinterop.*
import platform.CoreFoundation.*
import platform.Foundation.*
import platform.Security.*
import platform.posix.memcpy

fun ByteArray.toNSData(): NSData = memScoped {
    NSData.create(
        bytes = allocArrayOf(this@toNSData),
        length = this@toNSData.size.convert()
    )
}

fun NSData.toByteArray(): ByteArray = ByteArray(this@toByteArray.length.toInt()).apply {
    if (this@toByteArray.length > 0U) {
        usePinned {
            memcpy(it.addressOf(0), this@toByteArray.bytes, this@toByteArray.length)
        }
    }
}

@OptIn(ExperimentalUnsignedTypes::class)
fun ByteArray.toCFData(): CFDataRef = CFDataCreate(null, asUByteArray().refTo(0), size.toLong())!!

@OptIn(ExperimentalUnsignedTypes::class)
fun CFDataRef.toByteArray(): ByteArray {
    val length = CFDataGetLength(this)
    return UByteArray(length.toInt()).apply {
        val range = CFRangeMake(0, length)
        CFDataGetBytes(this@toByteArray, range, refTo(0))
    }.asByteArray()
}

actual object RSAPlatform {
    private fun getPrivateKeyFrom(pemString: String): SecKeyRef {
        val privateKeyPEM: String = pemString
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("\r\n", "")
            .replace("-----END PRIVATE KEY-----", "")

        memScoped {
            val keyNSData = NSData.create(privateKeyPEM.base64Decoded)!!
            val keyRef = CFBridgingRetain(NSData.create(privateKeyPEM.base64Decoded)) as CFDataRef
            val attributes: CFDictionaryRef? =
                CFDictionaryCreateMutable(null, 3, null, null)
            CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA)
            CFDictionaryAddValue(attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate)
            CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(keyNSData.length * 8u)))

            val keySpec = SecKeyCreateWithData(keyRef, attributes, null)

            return keySpec!!
        }
    }

    private fun getPublicKeyFrom(pemString: String): SecKeyRef {
        val publicKeyPEM: String = pemString
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("\r\n", "")
            .replace("-----END PUBLIC KEY-----", "")

        memScoped {
            val keyNSData = NSData.create(publicKeyPEM.base64Decoded)!!
            val keyRef = CFBridgingRetain(NSData.create(publicKeyPEM.base64Decoded)) as CFDataRef
            val attributes: CFDictionaryRef? =
                CFDictionaryCreateMutable(null, 3, null, null)
            CFDictionaryAddValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeRSA)
            CFDictionaryAddValue(attributes, kSecAttrKeyClass, kSecAttrKeyClassPublic)
            CFDictionaryAddValue(attributes, kSecAttrKeySizeInBits, CFBridgingRetain(NSNumber(keyNSData.length * 8u)))

            val keySpec = SecKeyCreateWithData(keyRef, attributes, null)
            return keySpec!!
        }
    }

    actual fun signSHA256RSA(privateKey: String, data: ByteArray): ByteArray {
        val key = getPrivateKeyFrom(privateKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaSHA256)
        val signedData = signer.signWithData(data.toNSData())!!
        return signedData.toByteArray()
    }

    actual fun signSHA384RSA(privateKey: String, data: ByteArray): ByteArray {
        val key = getPrivateKeyFrom(privateKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaSHA384)
        val signedData = signer.signWithData(data.toNSData())!!
        return signedData.toByteArray()
    }

    actual fun signSHA512RSA(privateKey: String, data: ByteArray): ByteArray {
        val key = getPrivateKeyFrom(privateKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaSHA512)
        val signedData = signer.signWithData(data.toNSData())!!
        return signedData.toByteArray()
    }

    actual fun signSHA256RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        val key = getPrivateKeyFrom(privateKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaPSSSHA256)
        val signedData = signer.signWithData(data.toNSData())!!
        return signedData.toByteArray()
    }

    actual fun signSHA384RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        val key = getPrivateKeyFrom(privateKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaPSSSHA384)
        val signedData = signer.signWithData(data.toNSData())!!
        return signedData.toByteArray()
    }

    actual fun signSHA512RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        val key = getPrivateKeyFrom(privateKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaPSSSHA512)
        val signedData = signer.signWithData(data.toNSData())!!
        return signedData.toByteArray()
    }

    actual fun verifySignSHA256RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val key = getPublicKeyFrom(publicKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaSHA256)
        return signer.verifyWithData(data.toNSData(), signedData.toNSData())
    }

    actual fun verifySignSHA384RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val key = getPublicKeyFrom(publicKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaSHA384)
        return signer.verifyWithData(data.toNSData(), signedData.toNSData())
    }

    actual fun verifySignSHA512RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val key = getPublicKeyFrom(publicKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaSHA512)
        return signer.verifyWithData(data.toNSData(), signedData.toNSData())
    }

    actual fun verifySignSHA256RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val key = getPublicKeyFrom(publicKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaPSSSHA256)
        return signer.verifyWithData(data.toNSData(), signedData.toNSData())
    }

    actual fun verifySignSHA384RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val key = getPublicKeyFrom(publicKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaPSSSHA384)
        return signer.verifyWithData(data.toNSData(), signedData.toNSData())
    }

    actual fun verifySignSHA512RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val key = getPublicKeyFrom(publicKey)
        val signer = RSASigner(key, RSASignatureMessageTypeRsaPSSSHA512)
        return signer.verifyWithData(data.toNSData(), signedData.toNSData())
    }
}