package io.iohk.atala.prism.apollo.derivation

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class DerivationPathTests {

    @Test
    fun deriveShouldReturnNewDerivationPathWithAddedAxis() {
        val path = DerivationPath.empty()
        val axis = DerivationAxis.normal(1)

        val derivedPath = path.derive(axis)

        assertEquals(path.axes + axis, derivedPath.axes)
    }

    @Test
    fun emptyShouldReturnNewDerivationPathWithNoAxes() {
        val path = DerivationPath.empty()

        assertTrue(path.axes.isEmpty())
    }

    @Test
    fun toStringShouldReturnCorrectStringRepresentation() {
        val axes = listOf(DerivationAxis.normal(1), DerivationAxis.hardened(2))
        val path = DerivationPath(axes)

        assertEquals("m/1/2'", path.toString())
    }

    @Test
    fun fromPathShouldParseStringAndReturnCorrespondingDerivationPath() {
        val pathStr = "m/1/2'"
        val path = DerivationPath.fromPath(pathStr)

        assertEquals(listOf(DerivationAxis.normal(1), DerivationAxis.hardened(2)), path.axes)
    }

    @Test
    fun fromPathShouldThrowExceptionOnIncorrectFormat() {
        val pathStr = "m'/1/2"

        assertFailsWith(IllegalArgumentException::class) {
            DerivationPath.fromPath(pathStr)
        }
    }

    @Test
    fun fromPathShouldThrowExceptionOnNegativeOrNonIntegerInput() {
        val pathStr = "m/-1/1.5"
        assertFailsWith(IllegalArgumentException::class) {
            DerivationPath.fromPath(pathStr)
        }
    }
}
