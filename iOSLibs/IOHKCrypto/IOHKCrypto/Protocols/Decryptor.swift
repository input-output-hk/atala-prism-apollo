//
//  Decryptor.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation

public protocol Decryptor {
    func decrypt(str: String, encoding: String.Encoding) -> String?
    func decrypt(str: String) -> Data?
    func decrypt(data: Data) -> Data?
}
