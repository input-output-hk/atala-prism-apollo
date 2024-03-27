package io.iohk.atala.prism.apollo.derivation

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class HDKeyOptionsTests {
    @Test
    fun propertiesShouldBeCorrectlyInitialized() {
        val versions = Pair(1, 2)
        val chainCode = ByteArray(32) // Arbitrary value
        val depth = 5
        val parentFingerprint = 123456789
        val index = BigInteger.ONE
        val privateKey = ByteArray(32)
        val publicKey = ByteArray(65)

        val hdKeyOptions = HDKeyOptions(versions, chainCode, depth, parentFingerprint, index, privateKey, publicKey)

        assertEquals(versions, hdKeyOptions.versions)
        assertEquals(chainCode.toList(), hdKeyOptions.chainCode.toList())
        assertEquals(depth, hdKeyOptions.depth)
        assertEquals(parentFingerprint, hdKeyOptions.parentFingerprint)
        assertEquals(index, hdKeyOptions.index)
        assertEquals(privateKey.toList(), hdKeyOptions.privateKey!!.toList())
        assertEquals(publicKey.toList(), hdKeyOptions.publicKey!!.toList())
    }

    @Test
    fun equalsShouldReturnTrueWhenComparedWithSameObjectAndFalseOtherwise() {
        val hdKeyOptions1 = HDKeyOptions(
            Pair(1, 2),
            ByteArray(32) { it.toByte() },
            5,
            123456789,
            BigInteger.ONE,
            ByteArray(32) { it.toByte() },
            ByteArray(65) { it.toByte() }
        )

        val hdKeyOptions2 = HDKeyOptions(
            Pair(1, 2),
            ByteArray(32) { it.toByte() },
            5,
            123456789,
            BigInteger.ONE,
            ByteArray(32) { it.toByte() },
            ByteArray(65) { it.toByte() }
        )

        val hdKeyOptions3 = HDKeyOptions(
            Pair(1, 2),
            ByteArray(32) { (it + 1).toByte() },
            5,
            123456789,
            BigInteger.ONE,
            ByteArray(32) { it.toByte() },
            ByteArray(65) { it.toByte() }
        )

        assertEquals(hdKeyOptions1, hdKeyOptions2)
        assertNotEquals(hdKeyOptions1, hdKeyOptions3)
    }

    @Test
    fun hashCodeShouldReturnSameValueForSameObjectAndDifferentValueForDifferentObject() {
        val hdKeyOptions1 = HDKeyOptions(
            Pair(1, 2),
            ByteArray(32) { it.toByte() },
            5,
            123456789,
            BigInteger.ONE,
            ByteArray(32) { it.toByte() },
            ByteArray(65) { it.toByte() }
        )

        val hdKeyOptions2 = HDKeyOptions(
            Pair(1, 2),
            ByteArray(32) { it.toByte() },
            5,
            123456789,
            BigInteger.ONE,
            ByteArray(32) { it.toByte() },
            ByteArray(65) { it.toByte() }
        )

        val hdKeyOptions3 = HDKeyOptions(
            Pair(1, 2),
            ByteArray(32) { (it + 1).toByte() },
            5,
            123456789,
            BigInteger.ONE,
            ByteArray(32) { it.toByte() },
            ByteArray(65) { it.toByte() }
        )

        assertEquals(hdKeyOptions1.hashCode(), hdKeyOptions2.hashCode())
        assertNotEquals(hdKeyOptions1.hashCode(), hdKeyOptions3.hashCode())
    }
}
