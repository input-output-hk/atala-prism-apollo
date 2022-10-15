package io.iohk.prism.apollo.hashing.internal

interface HMACInterface {
    /**
     * Create an HMAC [Digest] of the provided algorithm for creating hashes.
     *
     * @param key
     */
    public fun createHmac(key: ByteArray, outputLength: Int? = null): Digest = HMAC(this as Digest, key, outputLength)

    /**
     * Create an [HMAC] hash of [input] using the provided algorithm.
     */
    public fun hmac(key: ByteArray, input: ByteArray, outputLength: Int? = null): ByteArray = createHmac(key, outputLength).digest(input)
}
