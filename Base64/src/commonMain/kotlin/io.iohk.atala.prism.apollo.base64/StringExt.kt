package io.iohk.atala.prism.apollo.base64

// Base64Standard
/**
 * Encode a [String] to Base64 [String] standard encoding
 * RFC 4648 Section 4
 */
val String.base64Encoded: String
    get() = Base64.encode(this, Encoding.Standard)

/**
 * Decode a Base64 [String] standard encoded to [String].
 * RFC 4648 Section 4
 */
val String.base64Decoded: String
    get() = Base64.decode(this, Encoding.Standard).map {
        it.toChar()
    }.joinToString("").dropLast(count { it == '=' })

/**
 * Decode a Base64 [String] standard encoded to [ByteArray].
 * RFC 4648 Section 4
 */
val String.base64DecodedBytes: ByteArray
    get() = Base64.decode(this, Encoding.Standard).map {
        it.toByte()
    }.toList().dropLast(count { it == '=' }).toByteArray()

// Base64URL
/**
 * Encode a [String] to Base64 URL-safe encoded [String].
 * RFC 4648 Section 5
 * See [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5)
 */
val String.base64UrlEncoded: String
    get() = Base64.encode(this, Encoding.UrlSafe)

/**
 * Decode a Base64 URL-safe encoded [String] to [String].
 * RFC 4648 Section 5
 */
val String.base64UrlDecoded: String
    get() {
        val ret = Base64.decode(this, Encoding.UrlSafe).map { it.toChar() }
        val foo = ret.joinToString("")
        val bar = foo.dropLast(count { it == '=' })
        return bar.filterNot { it.code == 0 }
    }

/**
 * Decode a Base64 URL-safe encoded [String] to [ByteArray].
 * RFC 4648 Section 5
 */
val String.base64UrlDecodedBytes: ByteArray
    get() = Base64.decode(this, Encoding.UrlSafe).map {
        it.toByte()
    }.toList().dropLast(
        count {
            (it == '=') || (it == Char.MIN_VALUE)
        }
    ).toByteArray()
