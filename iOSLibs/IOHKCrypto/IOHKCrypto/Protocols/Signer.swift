//
//  Signer.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 19/10/2022.
//

import Foundation

public protocol Signer {
    func sign(data: Data) -> Data?
}
