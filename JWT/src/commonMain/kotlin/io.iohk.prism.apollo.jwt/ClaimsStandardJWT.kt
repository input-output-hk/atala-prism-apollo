package io.iohk.prism.apollo.jwt

import io.iohk.atala.prism.apollo.base64.base64Encoded
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.jvm.JvmOverloads

/**
 * A class representing the Standard JWT claims as described in
 * [RFC7519](https://tools.ietf.org/html/rfc7519#section-4.1).
 */
@Serializable
data class ClaimsStandardJWT @JvmOverloads constructor(
    override var exp: Long? = null,
    override var nbf: Long? = null,
    override var iat: Long? = null,
    override var iss: String? = null,
    override var sub: String? = null,
    override var aud: List<String>? = null,
    override var jti: String? = null
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
