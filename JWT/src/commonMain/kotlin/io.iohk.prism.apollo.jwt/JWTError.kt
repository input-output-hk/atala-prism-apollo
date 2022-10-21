package io.iohk.prism.apollo.jwt

sealed class JWTError(message: String?) : Exception(message) {
    /**
     * Error when an invalid JWT String is provided
     */
    final class InvalidJWTString(message: String? = "Input was not a valid JWT String") : JWTError(message)

    /**
     * Error when the JWT signiture fails verification.
     */
    final class FailedVerification(message: String? = "JWT verifier failed to verify the JWT String signature") : JWTError(message)

    /**
     * Error when an invalid private key is provided for RSA encryption.
     */
    final class InvalidPrivateKey(message: String? = "Provided private key could not be used to sign JWT") : JWTError(message)

    /**
     * Error when couldn't extract key from PEM
     */
    final class InvalidPEM(message: String? = "Couldn't get data from PEM key: no data available after stripping headers") : JWTError(message)
}
