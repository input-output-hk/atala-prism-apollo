//
//  RSA1024EncryptorTests.swift
//  IOHKCryptoTests
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import XCTest
@testable import IOHKCrypto
import CommonCrypto

class RSA1024EncryptorTests: XCTestCase {
    
    var sourceData: Data!
    var sourcedString: String!
    var privateKey: SecKey!
    var publicKey: SecKey!
    var rsaEncryptor: RSAEncryptor!
    var rsaDecryptor: RSADecryptor!
    
    override func setUp() {
        super.setUp()
        sourcedString = "+93654HJU)(ˆ% Hello RSA"
        sourceData = sourcedString.data(using: .utf8)!
        let tag = "com.example.keys.mykey".data(using: .utf8)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String:  kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits as String: 2048,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag
            ]
        ]
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            return
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            XCTFail("Failed to get public key")
            return
        }
        rsaEncryptor = RSAEncryptor(publicKey: publicKey, type: .rsaPKCS1)
        rsaDecryptor = RSADecryptor(privateKey: privateKey, type: .rsaPKCS1)
    }
    
    func test_encrypt_parametersData_returnData(){
        let encryptedData: Data? = rsaEncryptor.encrypt(data: sourceData)
        let decryptedData: Data? = rsaDecryptor.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_encrypt_parametersStringAndEncoding_returnString(){
        let encryptedString: String? = rsaEncryptor.encrypt(str: sourcedString)
        let decryptedString: String? = rsaDecryptor.decrypt(str: encryptedString!)
        XCTAssertEqual(sourcedString, decryptedString)
    }
    
    func test_encrypt_parametersStringAndEncoding_returnData(){
        let encryptedData: Data? = rsaEncryptor.encrypt(str: sourcedString)
        let decryptedData: Data? = rsaDecryptor.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData , decryptedData)
    }
    
    func test_decrypt_parametersData_returnData(){
        let encryptedData: Data? = rsaEncryptor.encrypt(data: sourceData)
        let decryptedData: Data? = rsaDecryptor.decrypt(data: encryptedData!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_decrypt_parametersString_returnData(){
        let encryptedString: String? = rsaEncryptor.encrypt(str: sourcedString)
        let decryptedData: Data? = rsaDecryptor.decrypt(str: encryptedString!)
        XCTAssertEqual(sourceData, decryptedData)
    }
    
    func test_decrypt_parametersStringAndEncoding_returnString(){
        let encryptedString: String? = rsaEncryptor.encrypt(str: sourcedString)
        let decryptedString: String? = rsaDecryptor.decrypt(str: encryptedString!)
        XCTAssertEqual(sourcedString, decryptedString)
    }
}
