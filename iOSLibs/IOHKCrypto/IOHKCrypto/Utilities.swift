//
//  Utilities.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation
import CommonCrypto

public class Utilities {
    public class func randomIv(length: Int) -> Data {
        return randomData(length: length)
    }
    
    public class func randomSalt(length: Int) -> Data {
        return randomData(length: length)
    }
    
    public class func randomData(length: Int) -> Data {
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { rawBufferPointer in
            let mutableBytes = rawBufferPointer.baseAddress!
            return SecRandomCopyBytes(kSecRandomDefault, length, mutableBytes)
        }
        assert(status == Int32(0))
        return data
    }
    
    public class func generateRandomData(_ length: Int) throws -> Data {
        let bytes = try Utilities.generateBytes(length)
        let data = Data(bytes: bytes, count: bytes.count)
        return data
    }
    
    public class func generateKey(varient: AESKeySize, password: Data, salt: Data) throws -> Data {
        let length = varient.value
        var status = Int32(0)
        var derivedBytes = [UInt8](repeating: 0, count: length)
        password.withUnsafeBytes { passwordBytes in
            let passwordBytes = passwordBytes.baseAddress!
            salt.withUnsafeBytes { saltBytes in
                let saltBytes = saltBytes.baseAddress!
                status = CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),                  // algorithm
                    passwordBytes,                                // password
                    password.count,                               // passwordLen
                    saltBytes,                                    // salt
                    salt.count,                                   // saltLen
                    CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),   // prf
                    10000,                                        // rounds
                    &derivedBytes,                                // derivedKey
                    length)                                       // derivedKeyLen
            }
        }
        guard status == 0 else { throw Error.keyGeneration(status: Int(status)) }
        return Data(bytes: derivedBytes, count: length)
    }
    
    public class func generateRandomDataFromString(_ length: Int) -> Data {
        let string = Utilities.randomString(length: length)
        return string.data(using: .utf8)!
    }
    
    class func createPublicKey(modulus: [UInt8], exponent: [UInt8], keySize: Int = 1024) -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            // kSecAttrIsPermanent as String: true as AnyObject,
            kSecAttrKeySizeInBits as String: keySize
        ]
        var modulusBytes : [UInt8] = modulus
        // Ensure the modulus is prefixed with 0x00.
        if let prefix = modulusBytes.first, prefix != 0x00 {
            modulusBytes.insert(0x00, at: 0)
        }
        var modulusEncoded: [UInt8] = []
        modulusEncoded.append(0x02)
        modulusEncoded.append(contentsOf: lengthField(of: modulusBytes))
        modulusEncoded.append(contentsOf: modulusBytes)
        
        var exponentEncoded: [UInt8] = []
        exponentEncoded.append(0x02)
        exponentEncoded.append(contentsOf: lengthField(of: exponent))
        exponentEncoded.append(contentsOf: exponent)
        
        var sequenceEncoded: [UInt8] = []
        sequenceEncoded.append(0x30)
        sequenceEncoded.append(contentsOf: lengthField(of: (modulusEncoded + exponentEncoded)))
        sequenceEncoded.append(contentsOf: (modulusEncoded + exponentEncoded))
        
        let keyData = Data(sequenceEncoded)
        // let base64PublicKey = keyData.base64EncodedString(options: .lineLength64Characters)
        let generatedPublicKey = SecKeyCreateWithData(keyData as CFData, attributes as CFDictionary, nil)
        return generatedPublicKey
    }
    
    private class func randomString(length: Int) -> String {
        let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ -/[]?.>,<)(*&^%$#@!~`+=\"'{}|:;"
        return String((0..<length).map{ _ in letters.randomElement()! })
    }
    
    private class func generateBytes(_ length: Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: UInt8(0), count: length)
        let statusCode = CCRandomGenerateBytes(&bytes, bytes.count)
        if statusCode != CCRNGStatus(kCCSuccess) {
            throw Error.keyGeneration(status: -1)
        }
        return bytes
    }
    
    private class func lengthField(of valueField: [UInt8]) -> [UInt8] {
        var count = valueField.count
        
        if count < 128 {
            return [UInt8(count)]
        }
        
        // The number of bytes needed to encode count.
        let lengthBytesCount = Int((log2(Double(count)) / 8) + 1)
        
        // The first byte in the length field encoding the number of remaining bytes.
        let firstLengthFieldByte = UInt8(128 + lengthBytesCount)
        
        var lengthField: [UInt8] = []
        for _ in 0..<lengthBytesCount {
            // Take the last 8 bits of count.
            let lengthByte = UInt8(count & 0xff)
            // Add them to the length field.
            lengthField.insert(lengthByte, at: 0)
            // Delete the last 8 bits of count.
            count = count >> 8
        }
        
        // Include the first byte.
        lengthField.insert(firstLengthFieldByte, at: 0)
        
        return lengthField
    }
}
