package io.iohk.prism.apollo.jwt

expect object RSAPlatform {
    fun signSHA256RSA(privateKey: String, data: ByteArray): ByteArray
    fun signSHA384RSA(privateKey: String, data: ByteArray): ByteArray
    fun signSHA512RSA(privateKey: String, data: ByteArray): ByteArray
    fun signSHA256RSAPSS(privateKey: String, data: ByteArray): ByteArray
    fun signSHA384RSAPSS(privateKey: String, data: ByteArray): ByteArray
    fun signSHA512RSAPSS(privateKey: String, data: ByteArray): ByteArray

    fun verifySignSHA256RSA(publicKey: String, data: ByteArray, signedData: ByteArray): Boolean
    fun verifySignSHA384RSA(publicKey: String, data: ByteArray, signedData: ByteArray): Boolean
    fun verifySignSHA512RSA(publicKey: String, data: ByteArray, signedData: ByteArray): Boolean
    fun verifySignSHA256RSAPSS(publicKey: String, data: ByteArray, signedData: ByteArray): Boolean
    fun verifySignSHA384RSAPSS(publicKey: String, data: ByteArray, signedData: ByteArray): Boolean
    fun verifySignSHA512RSAPSS(publicKey: String, data: ByteArray, signedData: ByteArray): Boolean
}