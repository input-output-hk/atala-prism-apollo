package io.iohk.prism.apollo.jwt

interface SignerAlgorithm {
    /**
     * A function to sign the header and claims of a JSON web token and return a signed JWT string.
     */
    fun sign(header: String, claims: String) : String
}
