// Automatically generated by dukat and then slightly adjusted manually to make it compile
@file:Suppress("ktlint", "internal:ktlint-suppression")
@file:JsModule("bip32")

package org.hyperledger.identus.apollo.utils.external

import node.buffer.Buffer
import kotlin.js.*

/**
 * Represents a key pair for BIP32 (Bitcoin Improvement Proposal 32).
 */
internal external interface Bip32KeyPair {
    var public: Number
    var private: Number
}

/**
 * Represents a network configuration.
 */
internal external interface Network {
    var wif: Number
    var bip32: Bip32KeyPair
    var messagePrefix: String?
        get() = definedExternally
        set(value) = definedExternally
    var bech32: String?
        get() = definedExternally
        set(value) = definedExternally
    var pubKeyHash: Number?
        get() = definedExternally
        set(value) = definedExternally
    var scriptHash: Number?
        get() = definedExternally
        set(value) = definedExternally
}

/**
 * BIP32Interface represents an interface for working with BIP32 keys.
 *
 * @property chainCode The chain code associated with the key.
 * @property network The network associated with the key.
 * @property lowR A flag indicating whether the key uses low R values.
 * @property depth The depth of the key in the hierarchical path.
 * @property index The index of the key in the hierarchical path.
 * @property parentFingerprint The fingerprint of the parent key.
 * @property publicKey The public key associated with the key.
 * @property privateKey The private key associated with the key. This property can be null.
 * @property identifier The identifier of the key.
 * @property fingerprint The fingerprint of the key.
 */
internal external interface BIP32Interface {
    var chainCode: Buffer
    var network: Network
    var lowR: Boolean
    var depth: Number
    var index: Number
    var parentFingerprint: Number
    var publicKey: Buffer
    var privateKey: Buffer?
        get() = definedExternally
        set(value) = definedExternally
    var identifier: Buffer
    var fingerprint: Buffer
    fun isNeutered(): Boolean
    fun neutered(): BIP32Interface
    fun toBase58(): String
    fun toWIF(): String
    fun derive(index: Number): BIP32Interface
    fun deriveHardened(index: Number): BIP32Interface
    fun derivePath(path: String): BIP32Interface
    fun sign(hash: Buffer, lowR: Boolean = definedExternally): Buffer
    fun verify(hash: Buffer, signature: Buffer): Boolean
}

/**
 * Converts a Base58 encoded string to a BIP32Interface object.
 *
 * @param inString The Base58 encoded string to convert.
 * @param network The network to use for the BIP32Interface object. Default is the defined external network.
 * @return The BIP32Interface object representing the decoded Base58 string.
 */
internal external fun fromBase58(inString: String, network: Network = definedExternally): BIP32Interface

/**
 * Creates a BIP32Interface instance from a private key, chain code, and optional network parameter.
 *
 * @param privateKey the private key as a Buffer
 * @param chainCode the chain code as a Buffer
 * @param network the optional network parameter, defaults to undefined
 * @return a BIP32Interface instance
 */
internal external fun fromPrivateKey(privateKey: Buffer, chainCode: Buffer, network: Network = definedExternally): BIP32Interface

/**
 * Constructs a BIP32Interface object from a public key, chain code, and network.
 *
 * @param publicKey The public key.
 * @param chainCode The chain code.
 * @param network The network (optional).
 * @return The BIP32Interface object.
 */
internal external fun fromPublicKey(publicKey: Buffer, chainCode: Buffer, network: Network = definedExternally): BIP32Interface

/**
 * Creates a BIP32Interface object from the given seed.
 *
 * @param seed The seed to generate the BIP32Interface object from.
 * @param network The network to use for generating the BIP32Interface object. Defaults to the value definedExternally.
 * @return The generated BIP32Interface object.
 */
internal external fun fromSeed(seed: Buffer, network: Network = definedExternally): BIP32Interface
