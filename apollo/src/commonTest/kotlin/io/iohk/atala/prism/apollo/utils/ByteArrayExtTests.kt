package io.iohk.atala.prism.apollo.utils

import kotlin.test.Test
import kotlin.test.assertEquals

class ByteArrayExtTests {
    @Test
    fun toHexStringShouldReturnCorrectStringForSingleByteArray() {
        val byteArray: ByteArray = byteArrayOf(0x1A)

        val expected = "1a"
        val actual = byteArray.toHexString()

        assertEquals(expected, actual)
    }

    @Test
    fun toHexStringShouldReturnCorrectStringForMultipleByteArray() {
        val byteArray: ByteArray = byteArrayOf(0x1A, 0x2F, 0xB1.toByte())

        val expected = "1a2fb1"
        val actual = byteArray.toHexString()

        assertEquals(expected, actual)
    }

    @Test
    fun toHexStringShouldReturnCorrectStringForEmptyByteArray() {
        val byteArray: ByteArray = byteArrayOf()

        val expected = ""
        val actual = byteArray.toHexString()

        assertEquals(expected, actual)
    }

    @Test
    fun testPadStartShouldReturnPaddedArrayWhenOriginalArrayLengthIsLessThanLength() {
        val byteArray: ByteArray = byteArrayOf(0x1A, 0x2F)

        val expected = ByteArray(5) { 0 }.apply {
            this[3] = 0x1A.toByte()
            this[4] = 0x2F.toByte()
        }
        val actual = byteArray.padStart(5, 0)

        assertEquals(expected.toList(), actual.toList())
    }

    @Test
    fun testPadStartShouldReturnOriginalArrayWhenOriginalArrayLengthIsEqualToLength() {
        val byteArray: ByteArray = byteArrayOf(0x1A, 0x2F)

        val expected = byteArray
        val actual = byteArray.padStart(2, 0)

        assertEquals(expected.toList(), actual.toList())
    }

    @Test
    fun testPadStartShouldReturnOriginalArrayWhenOriginalArrayLengthIsGreaterThanLength() {
        val byteArray: ByteArray = byteArrayOf(0x1A, 0x2F)

        val expected = byteArray
        val actual = byteArray.padStart(1, 0)

        assertEquals(expected.toList(), actual.toList())
    }
}
