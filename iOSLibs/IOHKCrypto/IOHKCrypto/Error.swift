//
//  Error.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation
import CommonCrypto

public enum Error: Swift.Error {
    case keyGeneration(status: Int)
    case cryptoFailed(status: CCCryptorStatus)
    case cryptoFailed(description: String)
    case invalidKeySize
    case invalidIVSizeOrLength
    case wrongVarientProvided
    case badInputVectorLength
}
