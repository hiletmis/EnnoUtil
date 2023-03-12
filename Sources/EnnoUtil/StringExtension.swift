//
//  File.swift
//  
//
//  Created by Hayrettin İletmiş on 8.03.2023.
//

import Foundation

extension String {

    func hexToBytes() -> [UInt8] {
        var hex = self
        hex = hex.replacingOccurrences(of: "0x", with: "")

        var length = hex.count

        if length & 1 != 0 {
            hex = "0" + hex
            length += 1
        }
        var bytes = [UInt8]()
        bytes.reserveCapacity(length/2)
        var index = hex.startIndex
        for _ in 0..<length/2 {
            let nextIndex = hex.index(index, offsetBy: 2)
            if let b = UInt8(hex[index..<nextIndex], radix: 16) {
                bytes.append(b)
            } else {
                return []
            }
            index = nextIndex
        }
        return bytes
    }

    private func stringFromResult(result: UnsafeMutablePointer<CUnsignedChar>, length: Int) -> String {
        let hash = NSMutableString()
        for i in 0..<length {
            hash.appendFormat("%02x", result[i])
        }
        return String(hash).lowercased()
    }
}
