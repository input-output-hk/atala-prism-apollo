package io.iohk.atala.prism.apollo.base64

/**
 * Base64 implementation
 */
final object Base64 {

    /**
     * Encode string to Base64
     */
    fun encode(string: String, encoding: Encoding = Encoding.Standard): String {
        val padLength = when (string.length % 3) {
            1 -> 2
            2 -> 1
            else -> 0
        }
        val raw = string + 0.toChar().toString().repeat(maxOf(0, padLength))
        val encoded = raw.chunkedSequence(3) {
            Triple(it[0].code, it[1].code, it[2].code)
        }.map { (first, second, third) ->
            (0xFF.and(first) shl 16) + (0xFF.and(second) shl 8) + 0xFF.and(third)
        }.map { n ->
            sequenceOf((n shr 18) and 0x3F, (n shr 12) and 0x3F, (n shr 6) and 0x3F, n and 0x3F)
        }.flatten()
            .map { encoding.alphabet[it] }
            .joinToString("")
            .dropLast(padLength)
        return when (encoding.requiresPadding) {
            true -> encoded.padEnd(encoded.length + padLength, '=')
            else -> encoded
        }
    }

    /**
     * Decode string to Base64
     */
    fun decode(string: String, encoding: Encoding = Encoding.Standard): Sequence<Int> {
        val padLength = when (string.length % 4) {
            1 -> 3
            2 -> 2
            3 -> 1
            else -> 0
        }
        return string.padEnd(string.length + padLength, '=')
            .replace("=", "A")
            .chunkedSequence(4) {
                (encoding.alphabet.indexOf(it[0]) shl 18) + (encoding.alphabet.indexOf(it[1]) shl 12) +
                    (encoding.alphabet.indexOf(it[2]) shl 6) + encoding.alphabet.indexOf(it[3])
            }
            .map { sequenceOf(0xFF.and(it shr 16), 0xFF.and(it shr 8), 0xFF.and(it)) }
            .flatten()
    }

    /**
     * Convert from Base64 to Base64Url
     */
    fun fromBase64ToBase64URL(from: String): String {
        return from.base64DecodedBytes.base64UrlEncoded
    }

    /**
     * Convert from Base64Url to Base64
     */
    fun fromBase64URLToBase64(from: String): String {
        return from.base64UrlDecodedBytes.base64Encoded
    }
}
