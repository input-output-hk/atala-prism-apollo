package io.iohk.atala.prism.apollo.utils

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StringExtTests {

    @Test
    fun testDecodeHexShouldCorrectlyDecodeHexadecimalString() {
        val hexString = "1a2fb1"
        val expected = byteArrayOf(0x1A.toByte(), 0x2F.toByte(), 0xB1.toByte())

        val actual = hexString.decodeHex()

        assertContentEquals(expected, actual)
    }

    @Test
    fun testDecodeHexShouldCorrectlyDecodeEmptyString() {
        val hexString = ""

        val actual = hexString.decodeHex()

        assertContentEquals(byteArrayOf(), actual)
    }

    @Test
    fun testDecodeHexShouldThrowIllegalArgumentExceptionForOddLengthString() {
        val hexString = "abc" // odd length string

        val exception = assertFailsWith<IllegalStateException> {
            hexString.decodeHex()
        }

        assertTrue(exception.message!!.contains("even length"))
    }
}
