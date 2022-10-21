//
//  Verifier.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 19/10/2022.
//

import Foundation

public protocol Verifier {
    func verify(data: Data, signedData: Data) -> Bool
}
