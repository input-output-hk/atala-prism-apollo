package io.iohk.atala.prism.apollo.uuid

import io.iohk.prism.apollo.hashing.MD5
import io.iohk.prism.apollo.hashing.SHA1
import kotlinx.datetime.Clock
import kotlinx.datetime.Instant
import kotlin.jvm.JvmStatic
import kotlin.random.Random
import kotlin.time.Duration

/**
 * UUID is an immutable representation of a 128-bit universally unique identifier (UUID).
 * RFC4122
 */
final class UUID {
    /**
     * The most significant 64 bits of this UUID.
     */
    var mostSigBits: Long
        private set

    /**
     * The least significant 64 bits of this UUID.
     */
    var leastSigBits: Long
        private set

    /**
     * The random number generator used by this class to create random based UUIDs.
     */
    private val numberGenerator = Random.Default

    /**
     * Private constructor which uses a byte array to construct the new UUID.
     */
    constructor(data: ByteArray) {
        var msb: Long = 0
        var lsb: Long = 0
        require(data.size == 16) {
            "data must be 16 bytes in length"
        }
        for (i in 0..7) {
            msb = msb shl 8 or (data[i].toInt() and 0xff).toLong()
        }
        for (i in 8..15) {
            lsb = lsb shl 8 or (data[i].toInt() and 0xff).toLong()
        }
        mostSigBits = msb
        leastSigBits = lsb
    }

    /**
     * Constructs a new [UUID] using the specified data. [mostSigBits] is used for the most significant 64 bits of the
     * [UUID] and [leastSigBits] becomes the least significant 64 bits of the [UUID].
     *
     * @param mostSigBits The most significant bits of the [UUID]
     * @param leastSigBits The least significant bits of the [UUID]
     */
    constructor(mostSigBits: Long, leastSigBits: Long) {
        this.mostSigBits = mostSigBits
        this.leastSigBits = leastSigBits
    }

    /**
     * The version number associated with this UUID. The version number describes how this UUID was
     * generated. The version number has the following meaning:
     * 1 Time-based UUID
     * 2 DCE security UUID
     * 3 Name-based UUID using [MD5]
     * 4 Randomly generated UUID
     * 5 Name-based UUID using [SHA1]
     * @return The version number of this UUID
     */
    fun version(): Int {
        // Version is bits masked by 0x000000000000F000 in MS long
        return (mostSigBits shr 12 and 0x0fL).toInt()
    }

    /**
     * The variant number associated with this UUID. The variant number describes the layout of the UUID.
     * The variant number has the following meaning:
     * 0 Reserved for NCS backward compatibility
     * 2 IETF RFC 4122  (Leach-Salz), used by this class
     * 6 Reserved, Microsoft Corporation backward compatibility
     * 7 Reserved for future definition
     * @return The variant number of this UUID
     */
    fun variant(): Int {
        // This field is composed of a varying number of bits.
        // 0    -    -    Reserved for NCS backward compatibility
        // 1    0    -    The IETF aka Leach-Salz variant (used by this class)
        // 1    1    0    Reserved, Microsoft backward compatibility
        // 1    1    1    Reserved for future definition.
        return (
            leastSigBits ushr (64 - (leastSigBits ushr 62)).toInt()
                and (leastSigBits shr 63)
            ).toInt()
    }

    /**
     * The timestamp value associated with this UUID.
     *
     * The 60 bit timestamp value is constructed from the time_low,
     * time_mid, and time_hi fields of this `UUID`.  The resulting
     * timestamp is measured in 100-nanosecond units since midnight,
     * October 15, 1582 UTC.
     *
     * The timestamp value is only meaningful in a time-based UUID, which
     * has version type 1.  If this `UUID` is not a time-based UUID then
     * this method throws UnsupportedOperationException.
     *
     * @throws UnsupportedOperationException If this UUID is not a version 1 UUID
     * @return The timestamp of this [UUID]
     */
    @Throws(UnsupportedOperationException::class)
    fun timestamp(): Long {
        if (version() != 1) {
            throw UnsupportedOperationException("Not a time-based UUID")
        }
        return mostSigBits and 0x0FFFL shl 48 or (
            mostSigBits shr 16 and 0x0FFFFL shl 32
            ) or (mostSigBits ushr 32)
    }

    /**
     * The clock sequence value associated with this UUID.
     *
     * The 14 bit clock sequence value is constructed from the clock
     * sequence field of this UUID.  The clock sequence field is used to
     * guarantee temporal uniqueness in a time-based UUID.
     *
     * The `clockSequence` value is only meaningful in a time-based
     * UUID, which has version type 1.  If this UUID is not a time-based UUID
     * then this method throws UnsupportedOperationException.
     *
     * @return The clock sequence of this `UUID`
     * @throws UnsupportedOperationException If this [UUID] is not a version 1 UUID
     */
    @Throws(UnsupportedOperationException::class)
    fun clockSequence(): Int {
        if (version() != 1) {
            throw UnsupportedOperationException("Not a time-based UUID")
        }
        return (leastSigBits and 0x3FFF000000000000L ushr 48).toInt()
    }

    /**
     * The node value associated with this UUID.
     *
     * The 48 bit node value is constructed from the node field of this
     * UUID.  This field is intended to hold the IEEE 802 address of the machine
     * that generated this UUID to guarantee spatial uniqueness.
     *
     * The node value is only meaningful in a time-based UUID, which has
     * version type 1. If this UUID is not a time-based UUID then this method
     * throws UnsupportedOperationException.
     *
     * @return The node value of this `UUID`
     * @throws UnsupportedOperationException If this UUID is not a version 1 UUID
     */
    @Throws(UnsupportedOperationException::class)
    fun node(): Long {
        if (version() != 1) {
            throw UnsupportedOperationException("Not a time-based UUID")
        }
        return leastSigBits and 0x0000FFFFFFFFFFFFL
    }

    override fun toString(): String {
        val builder = StringBuilder()
        val msbStr = mostSigBits.toHexString()
        if (msbStr.length < 16) {
            val diff = 16 - msbStr.length
            for (i in 0 until diff) {
                builder.append('0')
            }
        }
        builder.append(msbStr)
        builder.insert(8, '-')
        builder.insert(13, '-')
        builder.append('-')
        val lsbStr = leastSigBits.toHexString()
        if (lsbStr.length < 16) {
            val diff = 16 - lsbStr.length
            for (i in 0 until diff) {
                builder.append('0')
            }
        }
        builder.append(lsbStr)
        builder.insert(23, '-')
        return builder.toString()
    }

    companion object {
        /**
         * Static factory to retrieve a type 1 [UUID] based on the current timestamp, measured in units of
         * 100 nanoseconds from October 15, 1582
         *
         * @return A [UUID]
         */
        @JvmStatic
        fun randomUUID1(): UUID {
            fun generateMostSigBits(): Long {
                // //LocalDateTime(1582, 10, 15, 0, 0, 0)
                val start = Instant.parse("1582-10-15T00:00:00Z")
                val rightNow = Clock.System.now()
                val duration: Duration = start - rightNow
                val seconds: Long = duration.inWholeSeconds
                val nanos: Long = duration.inWholeNanoseconds
                val timeForUuidIn100Nanos = seconds * 10000000 + nanos * 100
                val least12SignificantBitOfTime = timeForUuidIn100Nanos and 0x000000000000FFFFL shr 4
                val version = (1 shl 12).toLong()
                return (timeForUuidIn100Nanos and -0x10000L) + version + least12SignificantBitOfTime
            }

            fun generateLeastSigBits(): Long {
                val random63BitLong = Random.Default.nextLong() and 0x3FFFFFFFFFFFFFFFL
                val variant3BitFlag = 0x8000000000000000U.toLong()
                return random63BitLong + variant3BitFlag
            }

            val mostSigBits = generateMostSigBits()
            val leastSigBits = generateLeastSigBits()

            return UUID(mostSigBits, leastSigBits)
        }

        /**
         * Static factory to retrieve a type 2 [UUID] based on a timestamp and the MAC address
         *
         * @return A [UUID]
         */
        @JvmStatic
        fun randomUUID2(): UUID {
            throw NotImplementedError("RFC 4122 does not specify the exact generation details, therefore it won't be implemented")
        }

        /**
         * Static factory to retrieve a type 3 (name based) [UUID] based on
         * the specified byte array.
         *
         * @param name A byte array to be used to construct a [UUID]
         * @return A [UUID] generated from the specified array
         */
        @JvmStatic
        fun randomUUID3(name: ByteArray): UUID {
            val hash = MD5()
            val md5Bytes = hash.digest(name)
            md5Bytes[6] = (md5Bytes[6].toInt() and 0x0f).toByte() // clear version
            md5Bytes[6] = (md5Bytes[6].toInt() or 0x30).toByte() // set to version 3
            md5Bytes[8] = (md5Bytes[8].toInt() and 0x3f).toByte() // clear variant
            md5Bytes[8] = (md5Bytes[8].toInt() or 0x80).toByte() // set to IETF variant
            return UUID(md5Bytes)
        }

        /**
         * Static factory to retrieve a type 4 (pseudo randomly generated) UUID. The UUID is generated using a
         * cryptographically strong pseudo random number generator.
         * @return: A randomly generated UUID
         */
        @JvmStatic
        fun randomUUID4(): UUID {
            var randomBytes = ByteArray(16)
            randomBytes = Random.Default.nextBytes(randomBytes)
            randomBytes[6] = (randomBytes[6].toInt() and 0x0f).toByte() // clear version
            randomBytes[6] = (randomBytes[6].toInt() or 0x40).toByte() // set to version 4
            randomBytes[8] = (randomBytes[8].toInt() and 0x3f).toByte() // clear variant
            randomBytes[8] = (randomBytes[8].toInt() or 0x80).toByte() // set to IETF variant
            return UUID(randomBytes)
        }

        /**
         * Static factory to retrieve a type 5 (name based) [UUID] based on
         * the specified byte array.
         *
         * @param name A byte array to be used to construct a [UUID]
         * @return A [UUID] generated from the specified array
         */
        @JvmStatic
        fun randomUUID5(name: ByteArray): UUID {
            val hash = SHA1()
            val sha1Bytes = hash.digest(name).copyOfRange(0, 16)
            sha1Bytes[6] = (sha1Bytes[6].toInt() and 0x0f).toByte() // clear version
            sha1Bytes[6] = (sha1Bytes[6].toInt() or 0x50).toByte() // set to version 3
            sha1Bytes[8] = (sha1Bytes[8].toInt() and 0x3f).toByte() // clear variant
            sha1Bytes[8] = (sha1Bytes[8].toInt() or 0x80).toByte() // set to IETF variant
            return UUID(sha1Bytes)
        }

        /**
         * Creates a [UUID] from the string standard representation as
         * described in the [toString] method.
         *
         * @param name A string that specifies a [UUID]
         * @return A [UUID] with the specified value
         * @throws IllegalArgumentException If name does not conform to the string representation as described in [toString]
         */
        @Throws(IllegalArgumentException::class)
        @JvmStatic
        fun fromString(name: String): UUID {
            val len = name.length
            if (len > 36) {
                throw IllegalArgumentException("UUID string too large")
            }

            val dash1 = name.indexOf('-', 0)
            val dash2 = name.indexOf('-', dash1 + 1)
            val dash3 = name.indexOf('-', dash2 + 1)
            val dash4 = name.indexOf('-', dash3 + 1)
            val dash5 = name.indexOf('-', dash4 + 1)

            // For any valid input, dash1 through dash4 will be positive and dash5
            // negative, but it's enough to check dash4 and dash5:
            // - if dash1 is -1, dash4 will be -1
            // - if dash1 is positive but dash2 is -1, dash4 will be -1
            // - if dash1 and dash2 is positive, dash3 will be -1, dash4 will be positive, but so will dash5
            if (dash4 < 0 || dash5 >= 0) {
                throw IllegalArgumentException("Invalid UUID string: $name")
            }

            var mostSigBits: Long = Long.parseLong(name, 0, dash1, 16) and 0xffffffffL
            mostSigBits = mostSigBits shl 16
            mostSigBits = mostSigBits or (Long.parseLong(name, dash1 + 1, dash2, 16) and 0xffffL)
            mostSigBits = mostSigBits shl 16
            mostSigBits = mostSigBits or (Long.parseLong(name, dash2 + 1, dash3, 16) and 0xffffL)
            var leastSigBits: Long = Long.parseLong(name, dash3 + 1, dash4, 16) and 0xffffL
            leastSigBits = leastSigBits shl 48
            leastSigBits = leastSigBits or (Long.parseLong(name, dash4 + 1, len, 16) and 0xffffffffffffL)

            return UUID(mostSigBits, leastSigBits)
        }

        /**
         * Just a simple method to determine if a character is valid hex in the
         * range ('0' - '9', 'a' - 'f', 'A' - 'F').
         * @param c A character to test.
         * @return True or false based on whether or not the character is in the expected range.
         */
        private fun validHex(c: Char): Boolean {
            return (c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F')
        }

        /**
         * This method validates a UUID String by making sure its non-null and calling isValidUUID(char[]).
         * @param id UUID String.
         * @return True or false based on whether the String can be used to construct a UUID.
         */
        @JvmStatic
        fun isValidUUID(id: String?): Boolean {
            return id != null && isValidUUID(id.toCharArray())
        }

        /**
         * This method validates a character array as the expected format for a printed representation of a UUID. The
         * expected format is 36 characters long, with '-' at the 8th, 13th, 18th, and 23rd characters. The remaining
         * characters are expected to be valid hex, meaning in the range ('0' - '9', 'a' - 'f', 'A' - 'F') inclusive.
         * If a character array is valid, then it can be used to construct a UUID. This method has been written unrolled
         * and verbosely, with the theory that this is simpler and faster than using loops or a regex.
         * @param ch A character array of a UUID's printed representation.
         * @return True or false based on whether the UUID is valid, no exceptions are thrown.
         */
        @JvmStatic
        fun isValidUUID(ch: CharArray?): Boolean {
            return ch != null && ch.size == 36 &&
                validHex(ch[0]) &&
                validHex(ch[1]) &&
                validHex(ch[2]) &&
                validHex(ch[3]) &&
                validHex(ch[4]) &&
                validHex(ch[5]) &&
                validHex(ch[6]) &&
                validHex(ch[7]) &&
                ch[8] == '-' &&
                validHex(ch[9]) &&
                validHex(ch[10]) &&
                validHex(ch[11]) &&
                validHex(ch[12]) &&
                ch[13] == '-' &&
                validHex(ch[14]) &&
                validHex(ch[15]) &&
                validHex(ch[16]) &&
                validHex(ch[17]) &&
                ch[18] == '-' &&
                validHex(ch[19]) &&
                validHex(ch[20]) &&
                validHex(ch[21]) &&
                validHex(ch[22]) &&
                ch[23] == '-' &&
                validHex(ch[24]) &&
                validHex(ch[25]) &&
                validHex(ch[26]) &&
                validHex(ch[27]) &&
                validHex(ch[28]) &&
                validHex(ch[29]) &&
                validHex(ch[30]) &&
                validHex(ch[31]) &&
                validHex(ch[32]) &&
                validHex(ch[33]) &&
                validHex(ch[34]) &&
                validHex(ch[35])
        }
    }
}
