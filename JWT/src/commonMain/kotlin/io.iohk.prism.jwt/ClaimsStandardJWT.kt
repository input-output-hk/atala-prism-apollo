package io.iohk.prism.jwt

data class ClaimsStandardJWT(
    override var exp: Long?,
    override var nbf: Long?,
    override var iat: Long?,
    override var iss: String?,
    override var sub: String?,
    override var aud: List<String>?,
    override var jti: String?
) : Claims