package io.iohk.atala.prism.apollo.derivation

import com.ionspin.kotlin.crypto.LibsodiumInitializer
import io.iohk.atala.prism.apollo.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

class SodiumTest {
    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun test() {
        LibsodiumInitializer.initializeWithCallback {
            val seedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
            val seed = seedHex.hexToByteArray()
            val result = Sodium().getMasterKeyFromSeed(seed)

            val a = Sodium().keygen(seed)
            val b = Sodium().keygen("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a".hexToByteArray())

            val expected = result.chainCode.toHexString()
            assertEquals("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", result.key.toHexString())
        }
    }
}
