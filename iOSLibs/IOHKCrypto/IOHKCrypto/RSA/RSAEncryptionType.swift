//
//  RSAEncryptionType.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation

@objc public enum RSAEncryptionType: Int {
    case rsaEncryption = 1
    case rsaPKCS1
    case rsaOAEPSHA1
    case rsaOAEPSHA224
    case rsaOAEPSHA256
    case rsaOAEPSHA384
    case rsaOAEPSHA512
    case rsaOAEPSHA1AESGCM
    case rsaOAEPSHA224AESGCM
    case rsaOAEPSHA256AESGCM
    case rsaOAEPSHA384AESGCM
    case rsaOAEPSHA512AESGCM
    
    var nativeValue: SecKeyAlgorithm {
        switch self {
        case .rsaEncryption:
            return .rsaEncryptionRaw
        case .rsaPKCS1:
            return .rsaEncryptionPKCS1
        case .rsaOAEPSHA1:
            return .rsaEncryptionOAEPSHA1
        case .rsaOAEPSHA224:
            return .rsaEncryptionOAEPSHA224
        case .rsaOAEPSHA256:
            return .rsaEncryptionOAEPSHA256
        case .rsaOAEPSHA384:
            return .rsaEncryptionOAEPSHA384
        case .rsaOAEPSHA512:
            return .rsaEncryptionOAEPSHA512
        case .rsaOAEPSHA1AESGCM:
            return .rsaEncryptionOAEPSHA1AESGCM
        case .rsaOAEPSHA224AESGCM:
            return .rsaEncryptionOAEPSHA224AESGCM
        case .rsaOAEPSHA256AESGCM:
            return .rsaEncryptionOAEPSHA256AESGCM
        case .rsaOAEPSHA384AESGCM:
            return .rsaEncryptionOAEPSHA384AESGCM
        case .rsaOAEPSHA512AESGCM:
            return .rsaEncryptionOAEPSHA512AESGCM
        }
    }
}
