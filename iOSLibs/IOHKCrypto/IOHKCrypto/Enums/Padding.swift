//
//  Padding.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation
import CommonCrypto

@objc public enum Padding: Int {
    case noPadding = 0, pkcs7Padding
}
