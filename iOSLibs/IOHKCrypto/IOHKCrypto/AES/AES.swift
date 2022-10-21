//
//  AES.swift
//  IOHKCrypto
//
//  Created by Ahmed Moussa on 13/10/2022.
//

import Foundation
import CommonCrypto
import CryptoKit

public protocol AESProtocol {
    /// CommonCrypto Context
    var context: UnsafeMutablePointer<CCCryptorRef?> { get }
    
    ///
    /// Updates the current calculation with data contained in an `NSData` object.
    ///
    /// - Parameter data: The `NSData` object
    ///
    func update(data: NSData)
    
    ///
    /// Updates the current calculation with data contained in an `Data` object.
    ///
    /// - Parameters data: The `Data` object
    ///
    func update(data: Data)
    
    ///
    /// Updates the current calculation with data contained in a byte array.
    ///
    /// - Parameter byteArray: The byte array
    ///
    func update(byteArray: [UInt8])
    
    ///
    /// Updates the current calculation with data contained in a String.
    /// The corresponding data will be generated using UTF8 encoding.
    ///
    /// - Parameter string: The string of data
    ///
    func update(string: String)
    
    ///
    ///    Upates the accumulated encrypted/decrypted data with the contents
    ///    of a raw byte buffer.
    ///
    ///    It is not envisaged the users of the framework will need to call this directly.
    ///
    func update(from buffer: UnsafeRawPointer, byteCount: Int)
    
    ///
    ///    Update the buffer
    ///
    /// - Parameters:
    ///        - bufferIn:         Pointer to input buffer
    ///        - inByteCount:         Number of bytes contained in input buffer
    ///        - bufferOut:         Pointer to output buffer
    ///        - outByteCapacity:     Capacity of the output buffer in bytes
    ///        - outByteCount:     On successful completion, the number of bytes written to the output buffer
    ///
    /// - Returns: Status of the update
    ///
    func update(bufferIn: UnsafeRawPointer, byteCountIn: Int, bufferOut: UnsafeMutablePointer<UInt8>, byteCapacityOut: Int, byteCountOut: inout Int)
    
    ///
    ///    Retrieves the encrypted or decrypted data.
    ///
    ///- Returns: the encrypted or decrypted data or nil if an error occured.
    ///
    func final() -> [UInt8]?
    
    ///
    ///    Retrieves all remaining encrypted or decrypted data from this cryptor.
    ///
    /// - Note: If the underlying algorithm is an block cipher and the padding option has
    /// not been specified and the cumulative input to the cryptor has not been an integral
    ///    multiple of the block length this will fail with an alignment error.
    ///
    /// - Note: This method updates the status property
    ///
    /// - Parameter byteArrayOut: The output bffer
    ///
    /// - Returns: a tuple containing the number of output bytes produced and the status (see Status)
    ///
    func final(byteArrayOut: inout [UInt8]) -> Int
    
    ///
    ///    Retrieves all remaining encrypted or decrypted data from this cryptor.
    ///
    /// - Note: If the underlying algorithm is an block cipher and the padding option has
    ///    not been specified and the cumulative input to the cryptor has not been an integral
    ///    multiple of the block length this will fail with an alignment error.
    ///
    /// - Note: This method updates the status property
    ///
    /// - Parameters:
    ///        - bufferOut:         Pointer to output buffer
    ///        - outByteCapacity:     Capacity of the output buffer in bytes
    ///        - outByteCount:     On successful completion, the number of bytes written to the output buffer
    ///
    /// - Returns: Status of the update
    ///
    func final(bufferOut: UnsafeMutablePointer<UInt8>, byteCapacityOut: Int, byteCountOut: inout Int)
    
    ///
    ///    Determines the number of bytes that will be output by this Cryptor if inputBytes of additional
    ///    data is input.
    ///
    /// - Parameters:
    ///        - inputByteCount:     Number of bytes that will be input.
    ///        - isFinal:             True if buffer to be input will be the last input buffer, false otherwise.
    ///
    /// - Returns: The final output length
    ///
    func getOutputLength(inputByteCount: Int, isFinal: Bool) -> Int
}

extension AESProtocol {
    
    public func update(data: NSData) {
        update(from: data.bytes, byteCount: size_t(data.length))
    }
    
    public func update(data: Data) {
        data.withUnsafeBytes {
            update(from: $0.baseAddress!, byteCount: size_t(data.count))
        }
    }
    
    public func update(byteArray: [UInt8]) {
        update(from: byteArray, byteCount: size_t(byteArray.count))
    }
    
    public func update(string: String) {
        update(from: string, byteCount: size_t(string.utf8.count))
    }
    
    public func final(byteArrayOut: inout [UInt8]) -> Int {
        let dataOutAvailable = byteArrayOut.count
        var dataOutMoved = 0
        final(bufferOut: &byteArrayOut, byteCapacityOut: dataOutAvailable, byteCountOut: &dataOutMoved)
        return dataOutMoved
    }
    
    public func final(bufferOut: UnsafeMutablePointer<UInt8>, byteCapacityOut: Int, byteCountOut: inout Int) {
        let rawStatus = CCCryptorFinal(self.context.pointee, bufferOut, byteCapacityOut, &byteCountOut)
        if rawStatus != kCCSuccess {
            fatalError("CCCryptorUpdate returned unexpected status.")
        }
    }
    
    public func getOutputLength(inputByteCount: Int, isFinal: Bool = false) -> Int {
        return CCCryptorGetOutputLength(self.context.pointee, inputByteCount, isFinal)
    }
}

@objc public class AESBase: NSObject, AESProtocol {
    /// CommonCrypto Context
    public private (set) var context = UnsafeMutablePointer<CCCryptorRef?>.allocate(capacity: 1)
    
    /// Internal accumulator for gathering data from the update() and final() functions.
    var accumulator: [UInt8] = []
    
    // MARK: - Helper methods
    public func update(from buffer: UnsafeRawPointer, byteCount: Int) {
        let outputLength = Int(self.getOutputLength(inputByteCount: byteCount, isFinal: false))
        var dataOut = Array<UInt8>(repeating: 0, count:outputLength)
        var dataOutMoved = 0
        update(bufferIn: buffer, byteCountIn: byteCount, bufferOut: &dataOut, byteCapacityOut: dataOut.count, byteCountOut: &dataOutMoved)
        accumulator += dataOut[0..<Int(dataOutMoved)]
    }
    
    public func update(bufferIn: UnsafeRawPointer, byteCountIn: Int, bufferOut: UnsafeMutablePointer<UInt8>, byteCapacityOut: Int, byteCountOut: inout Int) {
        let rawStatus = CCCryptorUpdate(self.context.pointee, bufferIn, byteCountIn, bufferOut, byteCapacityOut, &byteCountOut)
        if rawStatus != kCCSuccess {
            fatalError("CCCryptorUpdate returned unexpected status.")
        }
    }
    
    public func final() -> [UInt8]? {
        let byteCount = Int(self.getOutputLength(inputByteCount: 0, isFinal: true))
        var dataOut = Array<UInt8>(repeating: 0, count:byteCount)
        var dataOutMoved = 0
        dataOutMoved = final(byteArrayOut: &dataOut)
        accumulator += dataOut[0..<Int(dataOutMoved)]
        return accumulator
    }
    
    ///
    /// Zero pads a byte array such that it is an integral number of `blockSizeinBytes` long.
    ///
    /// - Parameters:
    ///    - byteArray:         The byte array
    ///     - blockSizeInBytes: The block size in bytes.
    ///
    /// - Returns: A Swift string
    ///
    public class func zeroPad(byteArray: [UInt8], blockSize: Int) -> [UInt8] {
        let pad = blockSize - (byteArray.count % blockSize)
        guard pad != 0 else {
            return byteArray
        }
        return byteArray + Array<UInt8>(repeating: 0, count: pad)
    }
}
