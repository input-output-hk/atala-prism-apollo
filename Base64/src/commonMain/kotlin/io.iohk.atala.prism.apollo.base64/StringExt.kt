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
    get() {
        val bytes = Base64.decode(this, Encoding.Standard).map {
            it.toByte()
        }.toList().dropLast(count { it == '=' }).toByteArray()
        val count = bytes.count {
            it.toInt() == 0
        }
        return bytes.dropLast(count).toByteArray()
    }

// Standard with Padding
/**
 * Encode a [String] to Base64 [String] standard encoding
 * RFC 4648 Section 4
 */
val String.base64PadEncoded: String
    get() = Base64.encode(this, Encoding.StandardPad)

/**
 * Decode a Base64 [String] standard encoded to [String].
 * RFC 4648 Section 4
 */
val String.base64PadDecoded: String
    get() = base64PadDecodedBytes.decodeToString()

/**
 * Decode a Base64 [String] standard encoded to [ByteArray].
 * RFC 4648 Section 4
 */
val String.base64PadDecodedBytes: ByteArray
    get() = Base64.decode(this, Encoding.StandardPad).map {
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
    get() = base64UrlDecodedBytes.decodeToString()

/**
 * Decode a Base64 URL-safe encoded [String] to [ByteArray].
 * RFC 4648 Section 5
 */
val String.base64UrlDecodedBytes: ByteArray
    get() {
        val bytes = Base64.decode(this, Encoding.UrlSafe).map {
            it.toByte()
        }.toList().dropLast(count { it == '=' || it.code == 0 }).toByteArray()
        val count = bytes.count {
            it.toInt() == 0
        }
        return bytes.dropLast(count).toByteArray()
    }

// Base64URL with padding
/**
 * Encode a [String] to Base64 URL-safe encoded [String].
 * RFC 4648 Section 5
 * See [RFC 4648 §5](https://datatracker.ietf.org/doc/html/rfc4648#section-5)
 */
val String.base64UrlPadEncoded: String
    get() = Base64.encode(this, Encoding.UrlSafePad)

/**
 * Decode a Base64 URL-safe encoded [String] to [String].
 * RFC 4648 Section 5
 */
val String.base64UrlPadDecoded: String
    get() = base64UrlPadDecodedBytes.decodeToString()

/**
 * Decode a Base64 URL-safe encoded [String] to [ByteArray].
 * RFC 4648 Section 5
 */
val String.base64UrlPadDecodedBytes: ByteArray
    get() = Base64.decode(this, Encoding.UrlSafePad).map {
        it.toByte()
    }.toList().dropLast(count { it == '=' }).toByteArray()
