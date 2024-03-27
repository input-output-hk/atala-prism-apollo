package io.iohk.atala.prism.apollo.derivation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class DerivationAxisTests {
    @Test
    fun hardenedShouldInitializeCorrectly() {
        val num = 15 // Just an arbitrary number for testing

        val hardenedDerivationAxis = DerivationAxis.hardened(num)

        assertEquals(num or (1 shl 31), hardenedDerivationAxis.i)
        assertTrue(hardenedDerivationAxis.hardened)
        assertEquals(num, hardenedDerivationAxis.number)
    }

    @Test
    fun hardenedShouldFailOnNegativeInput() {
        val num = -10
        assertFailsWith(IllegalArgumentException::class) {
            DerivationAxis.hardened(num)
        }
    }

    @Test
    fun normalShouldInitializeCorrectly() {
        val num = 20 // Just an arbitrary number for testing

        val normalDerivationAxis = DerivationAxis.normal(num)

        assertEquals(num, normalDerivationAxis.i)
        assertFalse(normalDerivationAxis.hardened)
        assertEquals(num, normalDerivationAxis.number)
    }

    @Test
    fun normalShouldFailOnNegativeInput() {
        val num = -10
        assertFailsWith(IllegalArgumentException::class) {
            DerivationAxis.hardened(num)
        }
    }

    @Test
    fun toStringShouldRenderCorrectly() {
        val num = 25

        val hardened = DerivationAxis.hardened(num)
        val normal = DerivationAxis.normal(num)

        assertEquals("$num'", hardened.toString())
        assertEquals(num.toString(), normal.toString())
    }

    @Test
    fun hashCodeShouldCalculateCorrectly() {
        val num = 30
        val derivationAxis = DerivationAxis.normal(num)

        assertEquals(num.hashCode(), derivationAxis.hashCode())
    }

    @Test
    fun equalsShouldWorkCorrectly() {
        val num1 = 35
        val num2 = 36

        val axis1 = DerivationAxis.normal(num1)
        val axisHardened1 = DerivationAxis.hardened(num2)
        val axis2 = DerivationAxis.normal(num2)

        assertEquals(axis1, axis1)
        assertNotEquals(axis1, axisHardened1)
        assertNotEquals(axis1, axis2)
    }
}
