package io.iohk.prism.apollo.jwt

sealed class JWTError(message: String?) : Exception(message) {
    final class InvalidJWTString(message: String? = "Input was not a valid JWT String") : JWTError(message)
    final class FailedVerification(message: String? = "JWT verifier failed to verify the JWT String signature") : JWTError(message)
}
