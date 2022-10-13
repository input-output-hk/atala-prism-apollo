//
//  RSAEncryptor.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation

@objc public class RSAEncryptor: NSObject, Encryptor {
    @objc private var publicKey: SecKey
    @objc public private(set) var type: RSAEncryptionType
    
    @objc public init(publicKey: SecKey, type: RSAEncryptionType) {
        self.publicKey = publicKey
        self.type = type
    }
    
    // MARK: - Encryptor
    public func encrypt(str: String, encoding: String.Encoding = .utf8) -> String? {
        return encrypt(str: str, encoding: encoding)?.base64EncodedString()
    }
    
    public func encrypt(str: String, encoding: String.Encoding = .utf8) -> Data? {
        if let strData = str.data(using: encoding) {
            return encrypt(data: strData)
        } else {
            return nil
        }
    }
    
    @objc public func encrypt(data: Data) -> Data? {
        let cfData = data as CFData
        var error: Unmanaged<CFError>?
        guard let cipherText = SecKeyCreateEncryptedData(publicKey, type.value, cfData, &error) as Data? else {
            return nil
        }
        return cipherText
    }
    
    // MARK: - Obj-c Helper function
    @objc public func encrypt(str: String) -> String? {
        return encrypt(str: str, encoding: .utf8)
    }
}
