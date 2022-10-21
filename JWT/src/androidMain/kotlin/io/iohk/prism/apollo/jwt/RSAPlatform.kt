package io.iohk.prism.apollo.jwt

import io.iohk.atala.prism.apollo.base64.base64DecodedBytes
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.*

actual object RSAPlatform {
    private fun getPrivateKeyFrom(pemString: String): RSAPrivateKey {
        val privateKeyPEM: String = pemString
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace(System.lineSeparator(), "")
            .replace("-----END PRIVATE KEY-----", "")
        val encoded: ByteArray = privateKeyPEM.base64DecodedBytes

        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = PKCS8EncodedKeySpec(encoded)
        return keyFactory.generatePrivate(keySpec) as RSAPrivateKey
    }

    private fun getPublicKeyFrom(pemString: String): RSAPublicKey {
        val publicKeyPEM: String = pemString
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace(System.lineSeparator(), "")
            .replace("-----END PUBLIC KEY-----", "")

        val encoded: ByteArray = publicKeyPEM.base64DecodedBytes

        val keyFactory = KeyFactory.getInstance("RSA")
        val keySpec = X509EncodedKeySpec(encoded)
        return (keyFactory.generatePublic(keySpec) as RSAPublicKey)
    }

    actual fun signSHA256RSA(privateKey: String, data: ByteArray): ByteArray {
        val privateKeyObj: RSAPrivateKey = getPrivateKeyFrom(privateKey)
        val signature: Signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKeyObj)
        signature.update(data)
        return signature.sign()
    }

    actual fun signSHA384RSA(privateKey: String, data: ByteArray): ByteArray {
        val privateKeyObj: RSAPrivateKey = getPrivateKeyFrom(privateKey)
        val signature: Signature = Signature.getInstance("SHA384withRSA")
        signature.initSign(privateKeyObj)
        signature.update(data)
        return signature.sign()
    }

    actual fun signSHA512RSA(privateKey: String, data: ByteArray): ByteArray {
        val privateKeyObj: RSAPrivateKey = getPrivateKeyFrom(privateKey)
        val signature: Signature = Signature.getInstance("SHA512withRSA")
        signature.initSign(privateKeyObj)
        signature.update(data)
        return signature.sign()
    }

    actual fun signSHA256RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        val privateKeyObj: RSAPrivateKey = getPrivateKeyFrom(privateKey)
        val signature: Signature = Signature.getInstance("SHA256withRSA/PSS")
        signature.initSign(privateKeyObj)
        signature.update(data)
        return signature.sign()
    }

    actual fun signSHA384RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        val privateKeyObj: RSAPrivateKey = getPrivateKeyFrom(privateKey)
        val signature: Signature = Signature.getInstance("SHA384withRSA/PSS")
        signature.initSign(privateKeyObj)
        signature.update(data)
        return signature.sign()
    }

    actual fun signSHA512RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        val privateKeyObj: RSAPrivateKey = getPrivateKeyFrom(privateKey)
        val signature: Signature = Signature.getInstance("SHA512withRSA/PSS")
        signature.initSign(privateKeyObj)
        signature.update(data)
        return signature.sign()
    }

    actual fun verifySignSHA256RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val publicKeyObj: RSAPublicKey = getPublicKeyFrom(publicKey)
        val signature: Signature = Signature.getInstance("SHA256withRSA")
        signature.initVerify(publicKeyObj)
        signature.update(data)
        return signature.verify(signedData)
    }

    actual fun verifySignSHA384RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val publicKeyObj: RSAPublicKey = getPublicKeyFrom(publicKey)
        val signature: Signature = Signature.getInstance("SHA384withRSA")
        signature.initVerify(publicKeyObj)
        signature.update(data)
        return signature.verify(signedData)
    }

    actual fun verifySignSHA512RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val publicKeyObj: RSAPublicKey = getPublicKeyFrom(publicKey)
        val signature: Signature = Signature.getInstance("SHA512withRSA")
        signature.initVerify(publicKeyObj)
        signature.update(data)
        return signature.verify(signedData)
    }

    actual fun verifySignSHA256RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val publicKeyObj: RSAPublicKey = getPublicKeyFrom(publicKey)
        val signature: Signature = Signature.getInstance("SHA256withRSA/PSS")
        signature.initVerify(publicKeyObj)
        signature.update(data)
        return signature.verify(signedData)
    }

    actual fun verifySignSHA384RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val publicKeyObj: RSAPublicKey = getPublicKeyFrom(publicKey)
        val signature: Signature = Signature.getInstance("SHA384withRSA/PSS")
        signature.initVerify(publicKeyObj)
        signature.update(data)
        return signature.verify(signedData)
    }

    actual fun verifySignSHA512RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        val publicKeyObj: RSAPublicKey = getPublicKeyFrom(publicKey)
        val signature: Signature = Signature.getInstance("SHA512withRSA/PSS")
        signature.initVerify(publicKeyObj)
        signature.update(data)
        return signature.verify(signedData)
    }
}