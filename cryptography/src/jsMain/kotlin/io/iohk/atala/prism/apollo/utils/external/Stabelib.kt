// Automatically generated by dukat and then slightly adjusted manually to make it compile
@file:Suppress("ktlint", "internal:ktlint-suppression", "SpellCheckingInspection")
@file:JsModule("@stablelib/x25519")

package io.iohk.atala.prism.apollo.utils.external

import js.typedarrays.Uint8Array

external var PUBLIC_KEY_LENGTH: Any

external var SECRET_KEY_LENGTH: Any

external var SHARED_KEY_LENGTH: Any

external fun scalarMult(n: Uint8Array, p: Uint8Array): Uint8Array

external fun scalarMultBase(n: Uint8Array): Uint8Array

external interface KeyPair {
    var publicKey: Uint8Array
    var secretKey: Uint8Array
}

external fun generateKeyPairFromSeed(seed: Uint8Array): KeyPair

external fun generateKeyPair(prng: dynamic = definedExternally): KeyPair

external fun sharedKey(mySecretKey: Uint8Array, theirPublicKey: Uint8Array, rejectZero: Boolean = definedExternally): Uint8Array
