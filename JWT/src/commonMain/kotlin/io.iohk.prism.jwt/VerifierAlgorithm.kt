package io.iohk.prism.jwt

interface VerifierAlgorithm {
    /**
     * A function to verify the signature of a JSON web token string is correct for the header and claims.
     */
    fun verify(jwt: String) : Boolean
}