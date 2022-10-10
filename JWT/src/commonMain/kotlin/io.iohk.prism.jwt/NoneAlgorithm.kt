package io.iohk.prism.jwt

/**
 * An EncryptionAlgorithm representing an alg of "none" in a JWT.
 * Using this algorithm means the header and claims will not be signed or verified.
 */
class NoneAlgorithm : VerifierAlgorithm, SignerAlgorithm {
    val name: String = "none"

    override fun sign(header: String, claims: String) : String {
        return "$header.$claims"
    }

    override fun verify(jwt: String) : Boolean {
        return true
    }
}
