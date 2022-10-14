//
//  Utilities.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation
import CommonCrypto

public class Utilities {
    ///
    /// Zero pads a byte array such that it is an integral number of `blockSizeinBytes` long.
    ///
    /// - Parameters:
     ///    - byteArray:         The byte array
    ///     - blockSizeInBytes: The block size in bytes.
    ///
    /// - Returns: A Swift string
    ///
    public static func zeroPad(byteArray: [UInt8], blockSize: Int) -> [UInt8] {
        let pad = blockSize - (byteArray.count % blockSize)
        guard pad != 0 else {
            return byteArray
        }
        return byteArray + Array<UInt8>(repeating: 0, count: pad)
    }
    
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
    
    public class func generateAESKey(algorithm: Algorithm, password: String, salt: String) throws -> Data {
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
    
    public class func generateRandomDataFromString(_ length: Int) -> Data {
        let string = Utilities.randomString(length: length)
        return string.data(using: .utf8)!
    }
    
    public class func randomString(length: Int) -> String {
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
}

extension String {

    func fromBase64() -> String? {
        guard let data = Data(base64Encoded: self) else {
            return nil
        }

        return String(data: data, encoding: .utf8)
    }

    func toBase64() -> String {
        return Data(self.utf8).base64EncodedString()
    }

}
