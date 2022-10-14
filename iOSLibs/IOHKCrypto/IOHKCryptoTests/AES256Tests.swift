//
//  AES256Tests.swift
//  IOHKCryptoTests
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import XCTest
@testable import IOHKCrypto
import CommonCrypto

class AES256Tests: XCTestCase {
    
    var sourceData: Data!
    var password: String!
    var salt: String!
    var iv: Data!
    var key: Data!
    var aesEncryptor: AESEncryptor!
    var aesDecryptor: AESDecryptor!
    var sourcedString: String!
    
    override func setUp() {
        super.setUp()
        do {
            sourcedString = "+93654HJU)(ˆ% Hello AES256"
            
            sourceData = sourcedString.data(using: .utf8)!
            password = "password"
            // print(sourceData.base64EncodedData())
            salt = Utilities.randomString(length: 8)
            iv = Utilities.randomIv(length: kCCBlockSizeAES128)
            key = try Utilities.generateAESKey(algorithm: .aes256, password: password, salt: salt)
            aesEncryptor = try AESEncryptor(algorithm: .aes256, options: .pkcs7Padding, mode: .cbc, padding: .pkcs7Padding, key: key, iv: iv)
            aesDecryptor = try AESDecryptor(algorithm: .aes256, options: .pkcs7Padding, mode: .cbc, padding: .pkcs7Padding, key: key, iv: iv)
        } catch let error {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test_encrypt_parametersData_returnData() {
        let encryptedData: Data? = aesEncryptor.encrypt(data: sourceData)
        let decryptedData: Data? = aesDecryptor.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_encrypt_parametersStringAndEncoding_returnString() {
        let encryptedString: String? = aesEncryptor.encrypt(str: sourcedString, encoding: .utf8)
        let decryptedString: String? = aesDecryptor.decrypt(str: encryptedString!, encoding: .utf8)
        XCTAssertEqual(sourcedString, decryptedString)
    }
    
    func test_encrypt_parametersStringAndEncoding_returnData() {
        let encryptedData: Data? = aesEncryptor.encrypt(str: sourcedString, encoding: .utf8)
        let decryptedData: Data? = aesDecryptor.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData , decryptedData)
    }
    
    func test_decrypt_parametersData_returnData() {
        let encryptedData: Data? = aesEncryptor.encrypt(data: sourceData)
        let decryptedData: Data? = aesDecryptor.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_decrypt_parametersString_returnData() {
        let encryptedString: String? = aesEncryptor.encrypt(str: sourcedString, encoding: .utf8)
        let decryptedData: Data? = aesDecryptor.decrypt(str: encryptedString!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_decrypt_parametersStringAndEncoding_returnString() {
        let encryptedString: String? = aesEncryptor.encrypt(str: sourcedString, encoding: .utf8)
        let decryptedString: String? = aesDecryptor.decrypt(str: encryptedString!, encoding: .utf8)
        XCTAssertEqual(sourcedString, decryptedString)
    }
}
