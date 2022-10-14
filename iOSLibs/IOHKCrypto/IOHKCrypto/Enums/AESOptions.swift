//
//  AESOptions.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 14/10/2022.
//

import Foundation
import CommonCrypto

///
/// Maps CommonCryptoOptions onto a Swift struct.
///
@objc public enum AESOptions: Int {
    /// No options
    case none = 1
    /// Use padding. Needed unless the input is a integral number of blocks long.
    case pkcs7Padding
    /// Electronic Code Book Mode. Don't use this.
    case ecbMode
    
    var nativeValue: CCOptions {
        switch self {
        case .none:
            return CCOptions()
        case .pkcs7Padding:
            return CCOptions(kCCOptionPKCS7Padding)
        case .ecbMode:
            return CCOptions(kCCOptionECBMode)
        }
    }
}
