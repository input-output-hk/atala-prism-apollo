package io.iohk.atala.prism.apollo.derivation

import com.ionspin.kotlin.bignum.integer.toBigInteger
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class BigIntegerWrapperTests {
    @Test
    fun initFromIntShouldInitializeValueCorrectly() {
        val intVal = Random.nextInt()
        val bigIntegerWrapper = BigIntegerWrapper(intVal)
        assertEquals(intVal.toBigInteger(), bigIntegerWrapper.value)
    }

    @Test
    fun initFromLongShouldInitializeValueCorrectly() {
        val longVal = Random.nextLong()
        val bigIntegerWrapper = BigIntegerWrapper(longVal)
        assertEquals(longVal.toBigInteger(), bigIntegerWrapper.value)
    }

    @Test
    fun initFromShortShouldInitializeValueCorrectly() {
        val shortVal = Random.nextInt(Short.MIN_VALUE.toInt(), Short.MAX_VALUE.toInt()).toShort()
        val bigIntegerWrapper = BigIntegerWrapper(shortVal)
        assertEquals(shortVal.toInt().toBigInteger(), bigIntegerWrapper.value)
    }

    @Test
    fun initFromByteShouldInitializeValueCorrectly() {
        val byteVal = Random.nextInt(Byte.MIN_VALUE.toInt(), Byte.MAX_VALUE.toInt()).toByte()
        val bigIntegerWrapper = BigIntegerWrapper(byteVal)
        assertEquals(byteVal.toInt().toBigInteger(), bigIntegerWrapper.value)
    }

    @Test
    fun initFromStringShouldInitializeValueCorrectly() {
        val strVal = Random.nextLong().toString()
        val bigIntegerWrapper = BigIntegerWrapper(strVal)
        assertEquals(strVal.toBigInteger(), bigIntegerWrapper.value)
    }

    @Test
    fun initFromBigIntegerShouldInitializeValueCorrectly() {
        val bigIntVal = Random.nextLong().toBigInteger()
        val bigIntegerWrapper = BigIntegerWrapper(bigIntVal)
        assertEquals(bigIntVal, bigIntegerWrapper.value)
    }

    @Test
    fun equalsShouldReturnTrueForSameObjectAndFalseForDifferentObject() {
        val bigIntegerWrapper1 = BigIntegerWrapper(Random.nextInt())
        val bigIntegerWrapper2 = BigIntegerWrapper(bigIntegerWrapper1.value)
        val bigIntegerWrapper3 = BigIntegerWrapper(Random.nextInt())

        assertEquals(bigIntegerWrapper1, bigIntegerWrapper2)
        assertNotEquals(bigIntegerWrapper1, bigIntegerWrapper3)
    }

    @Test
    fun hashCodeShouldReturnSameValueForSameObjectAndDifferentValueForDifferentObject() {
        val bigIntegerWrapper1 = BigIntegerWrapper(Random.nextInt())
        val bigIntegerWrapper2 = BigIntegerWrapper(bigIntegerWrapper1.value)
        val bigIntegerWrapper3 = BigIntegerWrapper(Random.nextInt())

        assertEquals(bigIntegerWrapper1.hashCode(), bigIntegerWrapper2.hashCode())
        assertNotEquals(bigIntegerWrapper1.hashCode(), bigIntegerWrapper3.hashCode())
    }
}
