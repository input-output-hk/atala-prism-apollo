package io.iohk.prism.apollo.jwt

import cocoapods.IOHKCrypto.*
import platform.Foundation.NSData

final class AES(
    private val algorithm: AESAlgorithmK,
    private val options: AESOptionsK,
    private val blockMode: BlockModeK,
    private val padding: PaddingK,
    private val key: ByteArray,
    private val iv: ByteArray?
) {

    fun encrypt(data: ByteArray): ByteArray? {
        val encryptor = AESEncryptor(
            algorithm.nativeValue(),
            options.nativeValue(),
            blockMode.nativeValue(),
            padding.nativeValue(),
            key.toNSData(),
            iv?.toNSData() ?: NSData(),
            null
        )
        return encryptor.encryptWithData(data.toNSData())?.toByteArray()
    }

    fun encrypt(str: String): String? {
        val encryptor = AESEncryptor(
            algorithm.nativeValue(),
            options.nativeValue(),
            blockMode.nativeValue(),
            padding.nativeValue(),
            key.toNSData(),
            iv?.toNSData() ?: NSData(),
            null
        )
        return encryptor.encryptWithStr(str)
    }

    fun decrypt(data: ByteArray): ByteArray? {
        val decryptor = AESDecryptor(
            algorithm.nativeValue(),
            options.nativeValue(),
            blockMode.nativeValue(),
            padding.nativeValue(),
            key.toNSData(),
            iv?.toNSData() ?: NSData(),
            null
        )
        return decryptor.decryptWithData(data.toNSData())?.toByteArray()
    }

    fun decrypt(str: String): String? {
        val decryptor = AESDecryptor(
            algorithm.nativeValue(),
            options.nativeValue(),
            blockMode.nativeValue(),
            padding.nativeValue(),
            key.toNSData(),
            iv?.toNSData() ?: NSData(),
            null
        )
        return decryptor.decryptWithStr(str)?.toByteArray().toString() // need to make [decryptWithStr] return String?
    }

    enum class PaddingK {
        No_Padding,
        PKCS7PADDING;

        fun nativeValue(): Padding {
            return when (this) {
                No_Padding -> PaddingNoPadding
                PKCS7PADDING -> PaddingPkcs7Padding
            }
        }
    }

    enum class BlockModeK {
        CBC,
        CFB,
        CFB8,
        CTR,
        ECB,
        GCM,
        Ofb,
        RC4;

        fun nativeValue(): BlockMode {
            return when (this) {
                CBC -> BlockModeCbc
                CFB -> BlockModeCfb
                CFB8 -> BlockModeCfb8
                CTR -> BlockModeCtr
                ECB -> BlockModeEcb
                GCM -> BlockModeGcm
                Ofb -> BlockModeOfb
                RC4 -> BlockModeRc4
            }
        }
    }

    enum class AESOptionsK {
        ECB_MODE,
        NONE,
        PKCS7PADDING;

        fun nativeValue(): AESOptions {
            return when (this) {
                ECB_MODE -> AESOptionsEcbMode
                NONE -> AESOptionsNone
                PKCS7PADDING -> AESOptionsPkcs7Padding
            }
        }
    }

    enum class AESAlgorithmK {
        AES_128,
        AES_192,
        AES_256;

        fun nativeValue(): AESAlgorithm {
            return when (this) {
                AES_128 -> AESAlgorithmAes128
                AES_192 -> AESAlgorithmAes192
                AES_256 -> AESAlgorithmAes256
            }
        }
    }
}