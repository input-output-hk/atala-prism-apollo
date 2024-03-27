package io.iohk.atala.prism.apollo

import kotlin.test.Test
import kotlin.test.assertTrue

class PlatformTests {
    @Test
    fun testOS() {
        assertTrue(Platform.OS.contains("JVM"))
    }
}
