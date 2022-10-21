//
//  Utilities.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation
import CommonCrypto

public class Utilities {
    private init() {}
    
    ///
    /// Generate random IV with provided length
    /// - Parameter length: length to the generated iv
    /// - Returns: random generated IV
    ///
    public class func randomIv(length: Int) -> Data {
        return randomData(length: length)
    }
    
    ///
    /// Generate random Salt with provided length
    /// - Parameter length: length to the generated Salt
    /// - Returns: random generated Salt
    ///
    public class func randomSalt(length: Int) -> Data {
        return randomData(length: length)
    }
    
    ///
    /// Generate random Data with provided length
    /// - Parameter length: length to the generated Data
    /// - Returns: random generated Data
    ///
    public class func randomData(length: Int) -> Data {
        var data = Data(count: length)
        let status = data.withUnsafeMutableBytes { rawBufferPointer in
            let mutableBytes = rawBufferPointer.baseAddress!
            return SecRandomCopyBytes(kSecRandomDefault, length, mutableBytes)
        }
        assert(status == Int32(0))
        return data
    }
    
    ///
    /// Generate random Data with provided length
    /// - Parameter length: length to the generated Data
    /// - Returns: random generated Data
    ///
    public class func generateRandomData(_ length: Int) throws -> Data {
        let bytes = try Utilities.generateBytes(length)
        let data = Data(bytes: bytes, count: bytes.count)
        return data
    }
    
    ///
    /// Generate AES encryption Key
    /// - Parameters:
    ///     - algorithm: AES algorithm type
    ///     - password: used for randomization
    ///     - salt: used for randomization
    /// - Returns: generated AES Key
    ///
    public class func generateAESKey(algorithm: AESAlgorithm, password: String, salt: String) throws -> Data {
        let length = algorithm.defaultKeySize
        var status = Int32(0)
        var derivedBytes = [UInt8](repeating: 0, count: length)
        status = CCKeyDerivationPBKDF(
            CCPBKDFAlgorithm(kCCPBKDF2),
            password,
            password.utf8.count,
            salt,
            salt.utf8.count,
            CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
            10000,
            &derivedBytes,
            length
        )
        guard status == 0 else { throw Error.keyGeneration(status: Int(status)) }
        return Data(bytes: derivedBytes, count: length)
    }
    
    ///
    /// Generate random Data with provided length from random generated string
    /// - Parameter length: length to the generated data
    /// - Returns: random generated Data
    ///
    public class func generateRandomDataFromString(_ length: Int) -> Data {
        let string = Utilities.randomString(length: length)
        return string.data(using: .utf8)!
    }
    
    ///
    /// Generate random string with provided length
    /// - Parameter length: length to the generated string
    /// - Returns: random generated String
    ///
    public class func randomString(length: Int) -> String {
        let letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ -/[]?.>,<)(*&^%$#@!~`+=\"'{}|:;"
        return String((0..<length).map{ _ in letters.randomElement()! })
    }
    
    ///
    /// Convert DER data to PEM data.
    ///
    ///    - Parameters:
    ///        - derData:  `Data` in DER format.
    ///        - type: Type of key data.
    ///
    ///    - Returns: PEM `Data` representation.
    ///
    public class func convertDerToPem(from derData: Data, type: RSAKey.KeyType) -> String {
        // First convert the DER data to a base64 string...
        let base64String = derData.base64EncodedString()
        
        // Split the string into strings of length 65...
        let lines = base64String.split(to: 65)
        
        // Join those lines with a new line...
        let joinedLines = lines.joined(separator: "\n")
        
        // Add the appropriate header and footer depending on whether the key is public or private...
        switch type {
        case .publicType:
            return ("-----BEGIN RSA PUBLIC KEY-----\n" + joinedLines + "\n-----END RSA PUBLIC KEY-----")
        case .privateType:
            return (IOHKCrypto.SK_BEGIN_MARKER + "\n" + joinedLines + "\n" + IOHKCrypto.SK_END_MARKER)
        }
    }
    
    ///
    /// Get the Base64 representation of a PEM encoded string after stripping off the PEM markers.
    ///
    /// - Parameters:
    ///        - pemString: `String` containing PEM formatted data.
    ///
    /// - Returns: Base64 encoded `String` containing the data.
    ///
    public class func base64String(for pemString: String) throws -> String {
        // Filter looking for new lines...
        var lines = pemString.components(separatedBy: "\n").filter { line in
            return !line.hasPrefix(IOHKCrypto.GENERIC_BEGIN_MARKER) && !line.hasPrefix(IOHKCrypto.GENERIC_END_MARKER)
        }
        
        // No lines, no data...
        guard lines.count != 0 else {
            throw Error.invalidBase64PEMData
        }
        
        // Strip off any carriage returns...
        lines = lines.map { $0.replacingOccurrences(of: "\r", with: "") }
        
        return lines.joined(separator: "")
    }
    
    ///
    /// This function strips the x509 from a provided ASN.1 DER public key. If the key doesn't contain a header,
    ///    the DER data is returned as is.
    ///
    /// - Parameters:
    ///        - keyData: `Data` containing the public key with or without the x509 header.
    ///
    /// - Returns: `Data` containing the public with header (if present) removed.
    ///
    public class func stripX509CertificateHeader(for keyData: Data) throws -> Data {
        // If private key in pkcs8 format, strip the header
        if keyData[26] == 0x30 {
            return(keyData.advanced(by: 26))
        }
        
        let count = keyData.count / MemoryLayout<CUnsignedChar>.size
        
        guard count > 0 else {
            throw Error.invalidPublicKey
        }
        
        let byteArray = [UInt8](keyData)
        
        var index = 0
        guard byteArray[index] == 0x30 else {
            throw Error.invalidASN1Key
        }
        
        index += 1
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        } else {
            index += 1
        }
        
        // If current byte marks an integer (0x02), it means the key doesn't have a X509 header and just
        // contains its modulo & public exponent. In this case, we can just return the provided DER data as is.
        if Int(byteArray[index]) == 0x02 {
            return keyData
        }
        
        // Now that we've excluded the possibility of headerless key, we're looking for a valid X509 header sequence.
        // It should look like this:
        // 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00
        guard Int(byteArray[index]) == 0x30 else {
            throw Error.invalidKeyX509Header
        }
        
        index += 15
        if byteArray[index] != 0x03 {
            throw Error.invalidKeyX509Header
        }
        
        index += 1
        if byteArray[index] > 0x80 {
            index += Int(byteArray[index]) - 0x80 + 1
        } else {
            index += 1
        }
        
        guard byteArray[index] == 0 else {
            throw Error.invalidKeyX509Header
        }
        
        index += 1
        
        let strippedKeyBytes = [UInt8](byteArray[index...keyData.count - 1])
        let data = Data(bytes: strippedKeyBytes, count: keyData.count - index)
        return data
    }
    
    ///
    /// Create a key from key data.
    ///
    /// - Parameters:
    ///        - keyData: `Data` representation of the key.
    ///        - type: Type of key data.
    ///
    ///    - Returns: `SecKey` representation of the key.
    ///
    public class func createKey(from keyData: Data, type: RSAKey.KeyType) throws ->  SecKey {
        let keyClass = type == .publicType ? kSecAttrKeyClassPublic : kSecAttrKeyClassPrivate
        
        let sizeInBits = keyData.count * MemoryLayout<UInt8>.size
        let keyDict: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: keyClass,
            kSecAttrKeySizeInBits: NSNumber(value: sizeInBits)
        ]
        
        guard let key = SecKeyCreateWithData(keyData as CFData, keyDict as CFDictionary, nil) else {
            throw Error.invalidKeyData
        }
        
        return key
    }
    
    private class func generateBytes(_ length: Int) throws -> [UInt8] {
        var bytes = [UInt8](repeating: UInt8(0), count: length)
        let statusCode = CCRandomGenerateBytes(&bytes, bytes.count)
        if statusCode != CCRNGStatus(kCCSuccess) {
            throw Error.keyGeneration(status: -1)
        }
        return bytes
    }
}
