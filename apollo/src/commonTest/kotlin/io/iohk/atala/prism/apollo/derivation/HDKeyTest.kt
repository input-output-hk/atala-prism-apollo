package io.iohk.atala.prism.apollo.derivation

import com.ionspin.kotlin.bignum.integer.BigInteger
import io.iohk.atala.prism.apollo.base64.base64UrlDecodedBytes
import io.iohk.atala.prism.apollo.derivation.HDKey.Companion.HARDENED_OFFSET
import io.iohk.atala.prism.apollo.utils.toHexString
import kotlin.random.Random
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class HDKeyTest {
    lateinit var seed: ByteArray
    lateinit var privateKey: String
    lateinit var derivedPrivateKey: String
    var childIndex = BigInteger(0)

    @BeforeTest
    fun setup() {
        seed =
            "e8uNN7LRH5mEUcxa7FhxDAgWGLh8P94WEOD0jUdaJ2mSU1o02u-Lzao50elV32XvYT0ux9jWuBVECpFAz2ckKw".base64UrlDecodedBytes
        privateKey = "96ViMAl0_N1Xm5RJesQxC2NvxhNc4ZkwPyVevZ4akDI"
        derivedPrivateKey = "xURclKhT6as1Tb9vg4AJRRLPAMWb9dYTTthDvXEKjMc"
    }

    @Test
    fun testConstructor_whenSeedIncorrectLength_thenThrowException() {
        val depth = 1
        childIndex = BigInteger(HARDENED_OFFSET)
        seed = seed.sliceArray(IntRange(0, 60))

        assertFailsWith(IllegalArgumentException::class) {
            HDKey(seed, depth, BigIntegerWrapper(childIndex))
        }
    }

    @Test
    fun testConstructorWithSeed_thenRightPrivateKey() {
        val depth = 0

        val hdKey = HDKey(seed = seed, depth = depth, childIndex = BigIntegerWrapper(childIndex))

        assertNotNull(hdKey.privateKey)
        assertTrue(privateKey.base64UrlDecodedBytes.contentEquals(hdKey.privateKey!!))
        assertNotNull(hdKey.chainCode)
        assertEquals(depth, hdKey.depth)
        assertEquals(BigIntegerWrapper(childIndex), hdKey.childIndex)
    }

    @Test
    fun testDerive_whenIncorrectPath_thenThrowException() {
        val depth = 1
        val hdKey = HDKey(seed, depth, BigIntegerWrapper(childIndex))
        val path = "x/0"

        assertFailsWith(Error::class) {
            hdKey.derive(path)
        }
    }

    @Test
    fun testDerive_whenCorrectPath_thenDeriveOk() {
        val depth = 1

        val hdKey = HDKey(seed, depth, BigIntegerWrapper(childIndex))
        val path = "m/0'/0'/0'"

        val derPrivateKey = hdKey.derive(path)
        assertTrue(derivedPrivateKey.base64UrlDecodedBytes.contentEquals(derPrivateKey.privateKey!!))
    }

    @Test
    fun testDeriveChild_whenNoChainCode_thenThrowException() {
        val depth = 1
        val hdKey =
            HDKey(
                privateKey = privateKey.encodeToByteArray(),
                depth = depth,
                childIndex = BigIntegerWrapper(childIndex)
            )

        assertFailsWith(Exception::class) {
            hdKey.deriveChild(BigIntegerWrapper(childIndex))
        }
    }

    @Test
    fun testDeriveChild_whenPrivateKeyNotHardened_thenThrowException() {
        val depth = 1
        val hdKey =
            HDKey(
                privateKey = privateKey.encodeToByteArray(),
                depth = depth,
                childIndex = BigIntegerWrapper(childIndex)
            )

        assertFailsWith(Exception::class) {
            hdKey.deriveChild(BigIntegerWrapper(childIndex))
        }
    }

    @Test
    fun testDeriveChild_whenPrivateKeyNotRightLength_thenThrowException() {
        val depth = 1
        childIndex = BigInteger(1)

        val hdKey =
            HDKey(
                privateKey = Random.Default.nextBytes(33),
                depth = depth,
                childIndex = BigIntegerWrapper(childIndex)
            )

        assertFailsWith(Exception::class) {
            hdKey.deriveChild(BigIntegerWrapper(childIndex))
        }
    }

    @Test
    fun testGetKMMSecp256k1PrivateKey_thenPrivateKeyNonNull() {
        val depth = 1

        val hdKey = HDKey(seed, depth, BigIntegerWrapper(childIndex))
        val key = hdKey.getKMMSecp256k1PrivateKey()
        assertNotNull(key)
    }

    // test vectors: https://github.com/satoshilabs/slips/blob/master/slip-0010.md#test-vector-2-for-ed25519
    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testFromSeed() {
        val seedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        val seed = seedHex.hexToByteArray()
        val key = HDKey.fromSeed("ed25519", seed)

        assertEquals("171cb88b1b3c1db25add599712e36245d75bc65a1a5c9e18d76f9f2b1eab4012", key.privateKey?.toHexString())
        assertEquals("ef70a74db9c3a5af931b5fe73ed8e1a53464133654fd55e7a66f8570b8e33c3b", key.chainCode?.toHexString())
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testFromSeed_Derive_1() {
        val seedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        val seed = seedHex.hexToByteArray()
        val key = HDKey.fromSeed("ed25519", seed)
        val derived = HDKey.deriveCurveFromPath("ed25519", key, "m/0'")

        assertEquals("1559eb2bbec5790b0c65d8693e4d0875b1747f4970ae8b650486ed7470845635", derived.privateKey?.toHexString())
        assertEquals("0b78a3226f915c082bf118f83618a618ab6dec793752624cbeb622acb562862d", derived.chainCode?.toHexString())
    }

    @OptIn(ExperimentalStdlibApi::class)
    @Test
    fun testFromSeed_Derive_2() {
        val seedHex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542"
        val seed = seedHex.hexToByteArray()
        val curve = "ed25519"
        val key = HDKey.fromSeed(curve, seed)
        val path = "m/0'/2147483647'"

        val d2 = HDKey.deriveCurveFromPath(curve, key, path)
        val d2key = d2.privateKey?.toHexString()
        val d2code = d2.chainCode?.toHexString()

        assertEquals("ea4f5bfe8694d8bb74b7b59404632fd5968b774ed545e810de9c32a4fb4192f4", d2key)
        assertEquals("138f0b2551bcafeca6ff2aa88ba8ed0ed8de070841f0c4ef0165df8181eaad7f", d2code)
    }

}
