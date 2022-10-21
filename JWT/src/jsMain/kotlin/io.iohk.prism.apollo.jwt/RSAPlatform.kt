package io.iohk.prism.apollo.jwt

actual object RSAPlatform {

    private fun getPrivateKey(pemString: String) {
        val str: String? = js("""
                function decodePrivatePem(pemString) {
                    local lines = split(pemString, "\n");
                    local start = -1;
                    local end = -1;
                    foreach (index, line in lines) {
                        if (line == "-----BEGIN RSA PRIVATE KEY-----") start = index + 1;
                        if (line == "-----END RSA PRIVATE KEY-----") end = index;
                    }
    
                    if (start != -1 && end > start) {
                        local all = lines.slice(start, end).reduce(@(a, b) a + b);
                        return http.base64decode(all);
                    }
    
                    return null;
                }
                decodePrivatePem(pemString);
            """) as? String

    }

    actual fun signSHA256RSA(privateKey: String, data: ByteArray): ByteArray {
        val result = js("""
            const crypto = require("crypto");
            crypto.sign("sha256", Buffer.from(verifiableData), {
              key: privateKey,
              padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            });
        """)
        return result as ByteArray
    }

    actual fun signSHA384RSA(privateKey: String, data: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun signSHA512RSA(privateKey: String, data: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun signSHA256RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun signSHA384RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun signSHA512RSAPSS(privateKey: String, data: ByteArray): ByteArray {
        TODO("Not yet implemented")
    }

    actual fun verifySignSHA256RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        TODO("Not yet implemented")
    }

    actual fun verifySignSHA384RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        TODO("Not yet implemented")
    }

    actual fun verifySignSHA512RSA(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        TODO("Not yet implemented")
    }

    actual fun verifySignSHA256RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        TODO("Not yet implemented")
    }

    actual fun verifySignSHA384RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        TODO("Not yet implemented")
    }

    actual fun verifySignSHA512RSAPSS(
        publicKey: String,
        data: ByteArray,
        signedData: ByteArray
    ): Boolean {
        TODO("Not yet implemented")
    }
}