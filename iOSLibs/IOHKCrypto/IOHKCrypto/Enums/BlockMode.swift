//
//  BlockMode.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation

@objc public enum BlockMode: CCMode {
    case ecb = 1, cbc, cfb, ctr, ofb, rc4, cfb8, gcm
    
    var needIV: Bool {
        switch self {
        case .cbc, .cfb, .ctr, .ofb, .cfb8, .gcm: return true
        default: return false
        }
    }
}
