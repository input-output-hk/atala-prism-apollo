//
//  AESKeySize.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation
import CommonCrypto

@objc public enum AESKeySize: Int {
    case aes128 = 1, aes192, aes256
    
    var value: Int {
        switch self {
        case .aes128:
            return kCCKeySizeAES128
        case .aes192:
            return kCCKeySizeAES192
        case .aes256:
            return kCCKeySizeAES256
        }
    }
    
    public static func getAESKeySizeFromKey(key: Data) throws -> AESKeySize {
        switch key.count {
        case kCCKeySizeAES128:
            return .aes128
        case kCCKeySizeAES192:
            return .aes192
        case kCCKeySizeAES256:
            return .aes256
        default:
            throw Error.badKeyLength
        }
    }
}
