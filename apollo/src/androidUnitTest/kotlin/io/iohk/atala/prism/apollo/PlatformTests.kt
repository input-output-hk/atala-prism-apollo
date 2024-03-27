package io.iohk.atala.prism.apollo

import org.junit.Test
import kotlin.test.assertTrue

class PlatformTests {
    @Test
    fun testOS() {
        assertTrue(Platform.OS.contains("Android"))
    }
}
