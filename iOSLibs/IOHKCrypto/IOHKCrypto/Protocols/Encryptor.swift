//
//  Encryptor.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation

public protocol Encryptor {
    func encrypt(str: String, encoding: String.Encoding) -> String?
    func encrypt(str: String, encoding: String.Encoding) -> Data?
    func encrypt(data: Data) -> Data?
}
