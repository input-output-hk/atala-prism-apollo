//
//  AES.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation
import CommonCrypto
import CryptoKit

@objc public class AES: NSObject, Cryptor {
    
    @objc public private (set) var key: Data
    @objc public private (set) var iv: Data
    @objc public private (set) var mode: BlockMode
    @objc public private (set) var padding: Padding
    @objc public private (set) var algorithm: CCAlgorithm
    @objc public private (set) var varient: AESKeySize
    
    @objc public init(key: Data, mode: BlockMode, iv: Data, padding: Padding) throws {
        self.varient = try AESKeySize.getAESKeySizeFromKey(key: key)
        if mode.needIV {
            if iv == Data() {
                throw Error.badInputVectorLength
            }
        }
        self.iv = iv
        self.key = key
        self.mode = mode
        self.algorithm = CCAlgorithm(self.varient.value)
        self.padding = padding
    }
    
    @objc public init(key: Data, varient: AESKeySize, mode: BlockMode, iv: Data, padding: Padding) throws {
        let checkVarient = try AESKeySize.getAESKeySizeFromKey(key: key)
        if varient == checkVarient {
            if mode.needIV {
                if iv == Data() {
                    throw Error.badInputVectorLength
                }
            }
            self.varient = varient
            self.iv = iv
            self.key = key
            self.mode = mode
            self.algorithm = CCAlgorithm(self.varient.value)
            self.padding = padding
        } else {
            throw Error.wrongVarientProvided
        }
    }
    
    // MARK: - Encryptor
    public func encrypt(str: String, encoding: String.Encoding = .utf8) -> String? {
        return encrypt(str: str, encoding: encoding)?.base64EncodedString()
    }
    
    public func encrypt(str: String, encoding: String.Encoding = .utf8) -> Data? {
        do {
            if let strData = str.data(using: encoding) {
                return try crypt(input: strData, operation: .encrypt)
            } else {
                return nil
            }
        } catch {
            return nil
        }
    }
    
    @objc public func encrypt(data: Data) -> Data? {
        do {
            return try crypt(input: data, operation: .encrypt)
        } catch {
            return nil
        }
    }
    
    // MARK: - Decryptor
    public func decrypt(str: String, encoding: String.Encoding = .utf8) -> String? {
        if let decryptedData: Data = decrypt(str: str) {
            return String(data: decryptedData, encoding: encoding)
        } else {
            return nil
        }
    }
    
    @objc public func decrypt(str: String) -> Data? {
        if let decodedStrData = Data(base64Encoded: str) {
            return decrypt(data: decodedStrData)
        } else {
            return nil
        }
    }
    
    @objc public func decrypt(data: Data) -> Data? {
        do {
            return try crypt(input: data , operation: .deccrypt)
        } catch {
            return nil
        }
    }
    
    // MARK: - Helper function
    private func crypt(input: Data, operation: AESOperation) throws -> Data {
        if mode == .gcm {
            let key = SymmetricKey(data: input)
            switch operation {
            case .encrypt:
                do {
                    let sealedBox = try CryptoKit.AES.GCM.seal(input, using: key, nonce: CryptoKit.AES.GCM.Nonce(data: iv))
                    return try CryptoKit.AES.GCM.open(sealedBox, using: key)
                } catch let ex {
                    throw Error.cryptoFailed(description: ex.localizedDescription)
                }
            case .deccrypt:
                do {
                    let sealedBox = try CryptoKit.AES.GCM.SealedBox(nonce:  CryptoKit.AES.GCM.Nonce(data: iv), ciphertext: input, tag: Data())
                    return try CryptoKit.AES.GCM.open(sealedBox, using: key)
                } catch let ex {
                    throw Error.cryptoFailed(description: ex.localizedDescription)
                }
            }
        }
        
        var outLength = Int(0)
        var outBytes = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        var status: CCCryptorStatus = CCCryptorStatus(kCCSuccess)
        let currentPadding: CCOptions
        switch padding {
        case .pkcs7Padding:
            currentPadding = CCOptions(kCCOptionPKCS7Padding)
        case .noPadding:
            currentPadding = CCOptions()
        }
        
        input.withUnsafeBytes { rawBufferPointer in
            let encryptedBytes = rawBufferPointer.baseAddress!
            iv.withUnsafeBytes { rawBufferPointer in
                let ivBytes = rawBufferPointer.baseAddress!
                key.withUnsafeBytes { rawBufferPointer in
                    let keyBytes = rawBufferPointer.baseAddress!
                    status = CCCrypt(
                        operation.value,    // operation
                        algorithm,          // algorithm
                        currentPadding,     // options
                        keyBytes,           // key
                        key.count,          // keylength
                        ivBytes,            // iv
                        encryptedBytes,     // dataIn
                        input.count,        // dataInLength
                        &outBytes,          // dataOut
                        outBytes.count,     // dataOutAvailable
                        &outLength)         // dataOutMoved
                }
            }
        }
        
        guard status == kCCSuccess else { throw Error.cryptoFailed(status: status) }
        
        return Data(bytes: &outBytes, count: outLength)
    }
    
    // MARK: - Obj-c Helper function
    @objc public func encrypt(str: String) -> String? {
        return encrypt(str: str, encoding: .utf8)
    }
    
    private enum AESOperation: CCOperation {
        case encrypt
        case deccrypt
        
        var value: CCOperation {
            switch self {
            case .encrypt:
                return CCOperation(kCCEncrypt)
            case .deccrypt:
                return CCOperation(kCCDecrypt)
            }
        }
    }
}
