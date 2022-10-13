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
    var salt: Data!
    var iv: Data!
    var key: Data!
    var aes: AES!
    var sourcedString: String!
    
    override func setUp() {
        super.setUp()
        do {
            sourcedString = "+93654HJU)(ˆ% Hello AES256"
            sourceData = sourcedString.data(using: .utf8)!
            password = "password"
            // print(sourceData.base64EncodedData())
            salt = Utilities.randomSalt(length: 8)
            iv = Utilities.randomIv(length: kCCBlockSizeAES128)
            key = try Utilities.generateKey(varient: .aes256, password: password.data(using: .utf8)!, salt: salt)
            aes = try AES(key: key, varient: .aes256, mode: .cbc, iv: iv, padding: .pkcs7Padding)
        } catch let error {
            XCTFail(error.localizedDescription)
        }
    }
    
    func test_encrypt_parametersData_returnData(){
        let encryptedData: Data? = aes.encrypt(data: sourceData)
        let decryptedData: Data? = aes.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_encrypt_parametersStringAndEncoding_returnString(){
        let encryptedString: String? = aes.encrypt(str: sourcedString, encoding: .utf8)
        let decryptedString: String? = aes.decrypt(str: encryptedString!, encoding: .utf8)
        XCTAssertEqual(sourcedString, decryptedString)
    }
    
    func test_encrypt_parametersStringAndEncoding_returnData(){
        let encryptedData: Data? = aes.encrypt(str: sourcedString, encoding: .utf8)
        let decryptedData: Data? = aes.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData , decryptedData)
    }
    
    func test_decrypt_parametersData_returnData(){
        let encryptedData: Data? = aes.encrypt(data: sourceData)
        let decryptedData: Data? = aes.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_decrypt_parametersString_returnData(){
        let encryptedString: String? = aes.encrypt(str: sourcedString, encoding: .utf8)
        let decryptedData: Data? = aes.decrypt(str: encryptedString!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_decrypt_parametersStringAndEncoding_returnString(){
        let encryptedString: String? = aes.encrypt(str: sourcedString, encoding: .utf8)
        let decryptedString: String? = aes.decrypt(str: encryptedString!, encoding: .utf8)
        XCTAssertEqual(sourcedString, decryptedString)
    }
}
