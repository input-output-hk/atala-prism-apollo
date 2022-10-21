//
//  RSASignatureMessageType.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 19/10/2022.
//

import Foundation

@objc public enum RSASignatureMessageType: Int {
    case rsaSHA256 = 1
    case rsaSHA384
    case rsaSHA512
    
    case rsaPSSSHA256
    case rsaPSSSHA384
    case rsaPSSSHA512
    
    var nativeValue: SecKeyAlgorithm {
        switch self {
        case .rsaSHA256:
            return .rsaSignatureMessagePKCS1v15SHA256
        case .rsaSHA384:
            return .rsaSignatureMessagePKCS1v15SHA384
        case .rsaSHA512:
            return .rsaSignatureMessagePKCS1v15SHA512
        case .rsaPSSSHA256:
            return .rsaSignatureMessagePSSSHA256
        case .rsaPSSSHA384:
            return .rsaSignatureMessagePSSSHA384
        case .rsaPSSSHA512:
            return .rsaSignatureMessagePSSSHA512
        }
    }
}
