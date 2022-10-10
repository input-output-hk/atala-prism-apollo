package io.iohk.prism.apollo.jwt

import io.iohk.atala.prism.apollo.base64.base64UrlDecoded
import kotlinx.datetime.Clock
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import kotlin.jvm.JvmOverloads
import kotlin.jvm.JvmStatic

/**
 * A class representing the `Header` and `Claims` of a JSON Web Token.
 */
class JWT {

    /**
     * The JWT header.
     */
    var header: JWTHeader

    /**
     * The JWT claims
     */
    var claims: ClaimsStandardJWT

    /**
     * Initialize a `JWT` instance from a `Header` and `Claims`.
     *
     * @param header A JSON Web Token header object.
     * @param claims A JSON Web Token claims object.
     */
    @JvmOverloads
    constructor(header: JWTHeader = JWTHeader(), claims: ClaimsStandardJWT) {
        this.header = header
        this.claims = claims
    }

    /**
     * Initialize a [JWT] instance from a JWT String.
     * The signature will be verified using the provided [JWTVerifier].
     * The time based standard JWT claims will be verified with [validateClaims()].
     * If the string is not a valid JWT, or the verification fails, the initializer returns nil.
     *
     * @param jwtString A String with the encoded and signed JWT.
     * @param verifier The [JWTVerifier] used to verify the JWT.
     * @throws [JWTError.InvalidJWTString] if the provided String is not in the form mandated by the JWT specification.
     * @throws [kotlinx.serialization.SerializationException] in case of any decoding-specific error
     * @throws [IllegalArgumentException]] if the decoded input is not
     */
    @Throws(
        JWTError.InvalidJWTString::class,
        kotlinx.serialization.SerializationException::class,
        IllegalArgumentException::class
    )
    constructor(jwtString: String, verifier: JWTVerifier = JWTVerifier.none()) {
        val components = jwtString.split(".")
        if (components.size == 2 || components.size == 3) {
            this.header = Json.Default.decodeFromString(components[0].base64UrlDecoded)
            this.claims = Json.Default.decodeFromString(components[1].base64UrlDecoded)
        } else {
            throw JWTError.InvalidJWTString()
        }
    }

    /**
     * Sign the JWT using the given algorithm and encode the header, claims and signature as a JWT String.
     *
     * @param jwtSigner The algorithm to sign with.
     * @return A String with the encoded and signed JWT.
     */
    fun sign(jwtSigner: JWTSigner) : String {
        val tempHeader = header
        tempHeader.alg = jwtSigner.name
        val headerString = this.header.encodeToBase64()
        val claimsString = this.claims.encodeToBase64()
        header.alg = tempHeader.alg
        return jwtSigner.sign(headerString, claimsString)
    }

    /**
     * Validate the time based standard JWT claims.
     * This function checks that the "exp" (expiration time) is in the future
     * and the "iat" (issued at) and "nbf" (not before) headers are in the past,
     *
     * @param leeway The time in seconds that the JWT can be invalid but still accepted to account for clock differences.
     * @return A value of [ValidateClaimsResult].
     */
    @JvmOverloads
    fun validateClaims(leeway: Long = 0) : ValidateClaimsResult {
        val currentEpochTime: Long = Clock.System.now().toEpochMilliseconds()
        claims.exp?.let {
            if (it + leeway < currentEpochTime) {
                return ValidateClaimsResult.EXPIRED
            }
        }

        claims.nbf?.let {
            if (it > currentEpochTime + leeway) {
                return ValidateClaimsResult.NOT_BEFORE
            }
        }

        claims.iat?.let {
            if (it > currentEpochTime + leeway) {
                return ValidateClaimsResult.ISSUED_AT
            }
        }

        return ValidateClaimsResult.SUCCESS
    }

    companion object {
        /**
         * Verify the signature of the encoded JWT using the given algorithm.
         *
         * @param jwt A String with the encoded and signed JWT.
         * @param jwtVerifier The algorithm to verify with.
         * @return A Bool indicating whether the verification was successful.
         */
        @JvmStatic
        fun verify(jwt: String, jwtVerifier: JWTVerifier) : Boolean {
            return jwtVerifier.verify(jwt)
        }
    }
}
