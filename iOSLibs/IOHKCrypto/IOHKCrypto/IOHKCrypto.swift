//
//  Constants.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 18/10/2022.
//

import Foundation

class IOHKCrypto {
    private init() {}
    
    /// PK Begin Marker
    static let PK_BEGIN_MARKER: String = "-----BEGIN PUBLIC KEY-----"

    /// PK End Marker
    static let PK_END_MARKER: String = "-----END PUBLIC KEY-----"

    /// SK Begin Marker
    static let SK_BEGIN_MARKER: String = "-----BEGIN RSA PRIVATE KEY-----"

    /// SK End Marker
    static let SK_END_MARKER: String = "-----END RSA PRIVATE KEY-----"

    /// Generic Begin Marker
    static let GENERIC_BEGIN_MARKER: String = "-----BEGIN"

    /// Generic End Marker
    static let GENERIC_END_MARKER: String = "-----END"
}
