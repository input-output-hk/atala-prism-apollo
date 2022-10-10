package io.iohk.prism.apollo.jwt

import io.iohk.atala.prism.apollo.base64.base64Encoded
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * A class representing the Standard JWT claims as described in
 * [RFC7519](https://tools.ietf.org/html/rfc7519#section-4.1).
 */
@Serializable
data class ClaimsStandardJWT(
    override var exp: Long?,
    override var nbf: Long?,
    override var iat: Long?,
    override var iss: String?,
    override var sub: String?,
    override var aud: List<String>?,
    override var jti: String?
) : Claims {

    /**
     * Convert it to JSON String then to Base64 string
     *
     * @return Base64 string representation of the [ClaimsStandardJWT]
     */
    fun encodeToBase64(): String {
        return Json.Default.encodeToString(this).base64Encoded
    }
}
