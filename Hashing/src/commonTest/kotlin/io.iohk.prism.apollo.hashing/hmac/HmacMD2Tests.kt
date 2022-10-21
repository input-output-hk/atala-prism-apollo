package io.iohk.prism.apollo.hashing.hmac

import io.iohk.prism.apollo.hashing.MD2
import io.iohk.prism.apollo.hashing.internal.JsIgnore
import io.iohk.prism.apollo.hashing.internal.toBinary
import io.iohk.prism.apollo.hashing.internal.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

@JsIgnore
class HmacMD2Tests : BaseHmacHashTests() {

    override fun hash(key: ByteArray, stringToHash: ByteArray, outputLength: Int?): String {
        val hash = MD2().createHmac(key, outputLength)
        return hash.digest(stringToHash).toHexString()
    }

    @Test
    fun test_Strings() {
        assertEquals("dc1923ef5f161d35bef839ca8c807808", hash("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "Hi There"))
    }

    @Test
    fun test_Seq() {
        val expectedOutput = listOf(
            "d39ad9dde006587a8be949b11b9288f8",
            "fcb21b5348c95e8a8dcbee50a80302ca",
            "2f26b6accd0e03fe9b21a1b0e75ff665",
            "17cf85d985d0d85f545897cd42c6efe5",
            "1537a6943b4f5ac1272e4161225d987b",
            "83e17165d62ca6e4b9ed67df1e599954",
            "7a3195c863dff86a98968f254e128e61",
            "bd05057aebfcb92fa4b07456085ec6c2",
            "23ac0d307bfc2e87760f8bdb21851df8",
            "2cd26a2f2994106a375beb0433575bde",
            "1f63bfc44fdbe9a966cd90df82265efd",
            "72735faadc3819cc24cfce1d589ba311",
            "28b589c3c8078b8ffef1c8297e33c1e6",
            "70a6dc014cad2752931a47c0879d2371",
            "81694317a37ffba816504974f38b4829",
            "72f26208b3051f1b938ea7e03dd8c107",
            "f945f57fe0696a4c81ec59ae69384fab",
            "54d8dfcee33969486956698495b4bfd0",
            "508b82f88a234e753a9e305e15a14d82",
            "527d77d2ab25131693b02f653acbd90e",
            "4868ac540fcc3a896d5a89f7a0444d36",
            "6189807c5fdddd68d20356adf3b90dc2",
            "0356362f2bc4206f2b930c4282213758",
            "2f59956f19b3cad687c66c4ec3cc916d",
            "e30cefbda3fa1a8edde3b72614addedf",
            "33e0e6bfcbc9581bbcdf13f4d3f26724",
            "b11c6476f9775219a9f18b5e88857790",
            "49c7a9d7f56344bd405e53be927e3a58",
            "99a06874b0f0ca45c9f29e05d213195f",
            "d21a60a18f061fc453ad5ac2a519071a",
            "2f735e82090144c036e3d12def2e0030",
            "f9539eac81bbcd0069a31e2a3c43769d",
            "edcaa9c85a614ab6a620b25af955d66a"
        )

        var key = ByteArray(16) {
            it.toByte()
        }

        expectedOutput.forEachIndexed { index, output ->
            assertEquals(output, hash(key, ByteArray(index) { it.toByte() }))
            key = output.toBinary()
        }
    }
}
