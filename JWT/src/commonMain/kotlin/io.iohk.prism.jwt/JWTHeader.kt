package io.iohk.prism.jwt

/**
 * A representation of a JSON Web Token header.
 */
data class JWTHeader(
    /**
     * Type Header Parameter
     */
    public var typ: String? = null,
    /**
     * Algorithm Header Parameter
     */
    public var alg: String? = null,
    /**
     * JSON Web Token Set URL Header Parameter
     */
    public var jku : String? = null,
    /**
     * JSON Web Key Header Parameter
     */
    public var jwk: String? = null,
    /**
     * Key ID Header Parameter
     */
    public var kid: String? = null,
    /**
     * X.509 URL Header Parameter
     */
    public var x5u: String? = null,
    /**
     * X.509 Certificate Chain Header Parameter
     */
    public var x5c: List<String>? = null,
    /**
     * X.509 Certificate SHA-1 Thumbprint Header Parameter
     */
    public var x5t: String? = null,
    /**
     * X.509 Certificate SHA-256 Thumbprint Header Parameter
     */
    public var x5tS256: String? = null,
    /**
     * Content Type Header Parameter
     */
    public var cty: String? = null,
    /**
     * Critical Header Parameter
     */
    public var crit: List<String>? = null
)