//
//  File.swift
//  
//
//  Created by Hayrettin İletmiş on 8.03.2023.
//

import Foundation
import CommonCrypto
import Crpytoworks

public class Web3Crypto {
    
    public class func getB32Root(seed: Seed, passphrase: String, version: VersionBytes) -> String? {
        if let rootKey = getRootKey(seed: seed, passphrase: passphrase) {
            return calcRootKey(rootKey: rootKey, version: version)
        }
        return nil
    }
    
    public class func getB32Root(rootKey: String, version: VersionBytes) -> String? {
        return calcRootKey(rootKey: rootKey, version: version)
    }
    
    public class func getXprv(seed: Seed, passphrase: String) -> String? {
        return nil
    }
    
    public class func getXprv(xPrv: String) -> String? {
        return nil
    }
    
    public class func getXpub(seed: Seed, passphrase: String) -> String? {
        return nil
    }
    
    public class func getXpub(xPrv: String) -> String? {
        return nil
    }
    
    public class func getBip39Seed(seed: Seed, passphrase: String) -> String? {
        if let pbkdf2 = pbkdf2(password: seed,
                               saltData: "mnemonic" + passphrase,
                               keyByteCount: 64,
                               prf: CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
                               rounds: 2048) {
            
            return pbkdf2.hexEncodedString()
        }
        return nil
    }
    
    public class func getHmac(bip39: String, key: String) -> String? {
        return bip39.hmac(algorithm: .SHA512, key: key)
    }
    
    public class func getRootKey(seed: Seed, passphrase: String) -> String? {
        if let bip39 = getBip39Seed(seed: seed, passphrase: passphrase) {
            return getHmac(bip39: bip39, key: "Bitcoin seed")
        }
        return nil
    }
    
    public class func getRootKey(bip39: String) -> String? {
        return getHmac(bip39: bip39, key: "Bitcoin seed")
    }
    
    private class func calcRootKey(rootKey: String, version: VersionBytes) -> String {
        let L = String(rootKey.prefix(64)).hexToBytes()
        let R = String(rootKey.suffix(64)).hexToBytes()
        
        let depthKey:[UInt8] = [0]
        let parentFingerprint:[UInt8] = [0,0,0,0]
        let childNumberBytes:[UInt8] = [0,0,0,0]
        let keyBytes:[UInt8] = [0] + L
        
        let versionBytes = version.rawValue.hexToBytes()
        let allParts:[UInt8] = versionBytes + depthKey + parentFingerprint + childNumberBytes + R + keyBytes
                    
        let checksum = CryptoFx.sha256(input: CryptoFx.sha256(input: allParts)).prefix(4)

        return Base58Encoder.encode(allParts + checksum)
    }
    
    private class func pbkdf2(password: String, saltData: String, keyByteCount: Int, prf: CCPseudoRandomAlgorithm, rounds: Int) -> Data? {
        guard let passwordData = password.data(using: .utf8) else { return nil }
        guard let saltData = saltData.data(using: .utf8) else { return nil }
        var derivedKeyData = Data(repeating: 0, count: keyByteCount)
        let derivedCount = derivedKeyData.count
        let derivationStatus: Int32 = derivedKeyData.withUnsafeMutableBytes { derivedKeyBytes in
            let keyBuffer: UnsafeMutablePointer<UInt8> =
                derivedKeyBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
            return saltData.withUnsafeBytes { saltBytes -> Int32 in
                let saltBuffer: UnsafePointer<UInt8> = saltBytes.baseAddress!.assumingMemoryBound(to: UInt8.self)
                return CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    password,
                    passwordData.count,
                    saltBuffer,
                    saltData.count,
                    prf,
                    UInt32(rounds),
                    keyBuffer,
                    derivedCount)
            }
        }
        return derivationStatus == kCCSuccess ? derivedKeyData : nil
    }
}
