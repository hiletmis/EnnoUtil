//
//  File.swift
//  
//
//  Created by Hayrettin İletmiş on 8.03.2023.
//

import Foundation
import Keccak 
import Blake2
import CommonCrypto

class CryptoFx {
    
    public class func blake2b256(input: Bytes) -> Bytes {
        
        var data = Data(count: WavesCryptoConstants.keyLength)
        var key: UInt8 = 0
        data.withUnsafeMutableBytes { (rawPointer) -> Void in
            guard let bytes = rawPointer.bindMemory(to: UInt8.self).baseAddress else { return }
            crypto_generichash_blake2b(bytes, WavesCryptoConstants.keyLength, input, UInt64(input.count), &key, 0)
        }
        
        return Array(data)
    }
    
    public class func keccak256(input: Bytes) -> Bytes {
        
        var data = Data(count: WavesCryptoConstants.keyLength)
        
        data.withUnsafeMutableBytes { (rawPointer) -> Void in
            guard let bytes = rawPointer.bindMemory(to: UInt8.self).baseAddress else { return }
            keccak(Array(input), Int32(input.count), bytes, 32)
        }
        
        return Array(data)
    }
    
    public class func sha256(input: Bytes) -> Bytes {
        
        let len = Int(CC_SHA256_DIGEST_LENGTH)
        var digest = [UInt8](repeating: 0, count: len)
        
        CC_SHA256(input, CC_LONG(input.count), &digest)
        
        return Array(digest[0..<len])
    }
    
}
