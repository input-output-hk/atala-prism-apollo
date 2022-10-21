//
//  RSASigner.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 18/10/2022.
//

import Foundation

@objc public class RSASigner: NSObject, Signer, Verifier {
    @objc private var key: SecKey
    @objc public private(set) var type: RSASignatureMessageType
    
    @objc public init(key: SecKey, type: RSASignatureMessageType) {
        self.key = key
        self.type = type
    }
    
    // MARK: - Signer
    @objc public func sign(data: Data) -> Data? {
        let cfData = data as CFData
        var error: Unmanaged<CFError>?
        guard let signedData = SecKeyCreateSignature(key, type.nativeValue, cfData, &error) as Data? else {
            return nil
        }
        return signedData
    }
    
    // MARK: - Verifier
    @objc public func verify(data: Data, signedData: Data) -> Bool {
        let cfData = data as CFData
        let cfSignedData = signedData as CFData
        var error: Unmanaged<CFError>?
        return SecKeyVerifySignature(key, type.nativeValue, cfData, cfSignedData, &error)
    }
}
