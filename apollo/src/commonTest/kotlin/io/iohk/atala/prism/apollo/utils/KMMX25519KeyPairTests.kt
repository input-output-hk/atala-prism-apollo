package io.iohk.atala.prism.apollo.utils

import kotlin.test.Test
import kotlin.test.assertNotNull

class KMMX25519KeyPairTests {
    @Test
    fun testGenerateKeyPair() {
        val keyPair = KMMX25519KeyPair.generateKeyPair()

        assertNotNull(keyPair)
        assertNotNull(keyPair.privateKey)
        assertNotNull(keyPair.publicKey)
    }

    @Test
    fun testGetPublicKeyFromPrivateKey() {
        val privateKey = KMMX25519KeyPair.generateKeyPair().privateKey
        assertNotNull(privateKey.publicKey())
    }
}
