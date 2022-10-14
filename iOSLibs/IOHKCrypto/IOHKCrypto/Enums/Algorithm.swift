//
//  Algorithm.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 14/10/2022.
//

import Foundation
import CommonCrypto

///
/// Enumerates available algorithms
///
@objc public enum Algorithm: Int {
    
    /// Advanced Encryption Standard
    /// - Note: aes and aes128 are equivalent.
    case aes128 = 1, aes192, aes256
    
    /// Blocksize, in bytes, of algorithm.
    public var blockSize: Int {
        switch self {
        case .aes128, .aes192, .aes256:
            return kCCBlockSizeAES128
        }
    }
    
    /// Default key size
    public var defaultKeySize: Int {
        switch self {
        case .aes128:
            return kCCKeySizeAES128
        case .aes192:
            return kCCKeySizeAES192
        case .aes256:
            return kCCKeySizeAES256
        }
    }
    
    /// Native, CommonCrypto constant for algorithm.
    public func nativeValue() -> CCAlgorithm {
        switch self {
        case .aes128, .aes192, .aes256:
            return CCAlgorithm(kCCAlgorithmAES)
        }
    }
    
    ///
    /// Tests if a given keySize is valid for this algorithm
    ///
    /// - Parameter keySize: The key size to be validated.
    ///
    /// - Returns: True if valid, false otherwise.
    ///
    public func isValidKeySize(keySize: Int) -> Bool {
        return [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].contains(keySize)
    }
    
    ///
    /// Calculates the next, if any, valid keySize greater or equal to a given `keySize` for this algorithm
    ///
    /// - Parameter keySize: Key size for which the next size is requested.
    ///
    /// - Returns: Next key size or nil
    ///
    public func paddedKeySize(keySize: Int) -> Int? {
        return [kCCKeySizeAES128, kCCKeySizeAES192, kCCKeySizeAES256].sorted().reduce(nil) { answer, current in
            return answer ?? ((current >= keySize) ? current : nil)
        }
    }
}
