//
//  RSADecryptor.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation

@objc public class RSADecryptor: NSObject, Decryptor {
    @objc private var privateKey: SecKey
    @objc public private(set) var type: RSAEncryptionType
    
    @objc public init(privateKey: SecKey, type: RSAEncryptionType) {
        self.privateKey = privateKey
        self.type = type
    }
    
    // MARK: - Decryptor
    public func decrypt(str: String, encoding: String.Encoding = .utf8) -> String? {
        if let decryptedData: Data = decrypt(str: str) {
            return String(data: decryptedData, encoding: encoding)
        } else {
            return nil
        }
    }
    
    public func decrypt(str: String) -> Data? {
        if let data = Data(base64Encoded: str) {
            return decrypt(data: data)
        } else {
            return nil
        }
    }
    
    @objc public func decrypt(data: Data) -> Data? {
        let cfData = data as CFData
        var error: Unmanaged<CFError>?
        guard let decryptedData = SecKeyCreateDecryptedData(privateKey, type.value, cfData, &error) as Data? else {
            return nil
        }
        return decryptedData
    }
    
    // MARK: - Obj-c Helper function
    @objc public func decrypt(str: String) -> String? {
        return decrypt(str: str, encoding: .utf8)
    }
}
