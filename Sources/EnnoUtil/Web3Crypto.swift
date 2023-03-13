//
//  File.swift
//  
//
//  Created by Hayrettin İletmiş on 8.03.2023.
//

import Foundation
import CommonCrypto
import B58
import Web3Util

public class Web3Crypto {
    
    private static let SECP256k1_ORD = "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"

    public class func getBip32Key(seed: Seed) -> BIP32KeyPair {
        let binarySeed = Mnemonic.toBinarySeed(mnemonicPhrase: seed)
        return BIP32KeyPair(fromSeed: binarySeed)
    }
    
    public class func getBip32Key(binarySeed: [UInt8]) -> BIP32KeyPair {
        return BIP32KeyPair(fromSeed: binarySeed)
    }
    
    public class func getFingerprint(seed: Seed) -> [UInt8]? {
        let keyPair = getBip32Key(seed: seed)
        
        if let privKey = keyPair.privateKey {
            return fingerprintFromPrivKey(privKey: privKey)
        }
        
        return nil
    }
    
    public class func Account(path: String, key: BIP32KeyPair) -> Web3Account? {
        if let extendedPrivateKey = deriveExtPrivKey(path: path, key: key) {
            let privKey = Array(extendedPrivateKey[46...77])
            let pubKey = PublicKey(privKey: privKey)
            let address = Address(privateKey: privKey)
            
            return Web3Account.init(address: "0x" + address,
                                    publicKey: "0x" + pubKey,
                                    privateKey: "0x" + privKey.toHexString())
        }
        return nil
    }
    
    
    public class func PublicKey(privKey: String, compressed: Bool = false) -> String {
        PublicKey(privKey: privKey.hexToBytes(), compressed: compressed)
    }
    
    public class func PublicKey(privKey: [UInt8], compressed: Bool = false) -> String {
        Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: compressed)
    }
    
    public class func Address(publicKey: String) -> String {
        Web3Util.Key.getAddressFromPublicKey(publicKey: publicKey.hexToBytes())
    }
    
    public class func Address(privateKey: String) -> String {
        Address(privateKey: privateKey.hexToBytes())
    }
    
    public class func Address(privateKey: [UInt8]) -> String {
        Web3Util.Key.getAddressFromPrivateKey(privKey: privateKey)
    }

    public class func deriveExtPrivKey(xPrv: String, depth: Int, index: Int) -> [UInt8]? {
        let path = "m/\(index)"
        let key = Base58Encoder.decode(xPrv)
        let privKey:[UInt8] = Array(key[46...77])
        let chainCode:[UInt8] = Array(key[13...44])

        let xPriv = BIP32KeyPair.init(privateKey: privKey, chainCode: chainCode, publicKey: nil)
        return deriveExtPrivKey(path: path, key: xPriv, depth: depth)
    }
    
    public class func deriveExtPrivKey(path: String, key: BIP32KeyPair, depth: Int = 0) -> [UInt8]? {
        
        if !testPath(path: path) {
            return nil
        }
        
        let hardened = 2147483648
        
        var pathNumbers: [Int] = []
        
        var paths = path.split(separator: "/")
        paths.removeFirst()

        for p in paths {
            let isHardened = p.contains("'")
            let integerValue = Int(p.replacingOccurrences(of: "'", with: "")) ?? 0
            
            pathNumbers.append(isHardened ? integerValue + hardened : integerValue)
        }
                
        guard let masterPrivKey = key.privateKey else { return nil }
        guard let masterChainCode = key.chainCode else { return nil }

        var depth = depth
        var parentFingerprint:[UInt8] = []
        var childNumber = 0
        var privateKey = masterPrivKey
        var chainCode = masterChainCode
        
        for item in pathNumbers {
            depth += 1
            
            childNumber = item
            parentFingerprint = fingerprintFromPrivKey(privKey: privateKey)
            
            let key = BIP32KeyPair.init(privateKey: privateKey, chainCode: chainCode, publicKey: nil)
            
            if let (privKey, derivedChainCode) = derivePath(key: key, childNumber: childNumber) {
                privateKey = privKey
                chainCode = derivedChainCode
            } else {
                return nil
            }
        }
        
        let keyBytes:[UInt8] = [0] + privateKey
        let depthKey = byteArray(from: depth).suffix(1)
        let childNumberBytes = byteArray(from: childNumber).suffix(4)
        
        let versionBytes = VersionBytes.mainnetPrivate.rawValue.hexToBytes()
        let allParts:[UInt8] = versionBytes + depthKey + parentFingerprint + childNumberBytes + chainCode + keyBytes
        
        return checksum(datas: allParts)
    }
    
    public class func deriveAddress(path: String, key: BIP32KeyPair) -> [UInt8]? {
        if let extendedPrivateKey = deriveExtPrivKey(path: path, key: key) {
            let privateKey:[UInt8] = Array(extendedPrivateKey[46...77])
            return Address(privateKey: privateKey).hexToBytes()
        }
        return nil
    }
    
    public class func deriveAddress(xPriv: Web3ExtPrivateKey, depth:Int, index: Int) -> [UInt8]? {
        if let extendedPrivateKey = deriveExtPrivKey(xPrv: xPriv, depth: depth, index: index) {
            let privateKey:[UInt8] = Array(extendedPrivateKey[46...77])
            return Address(privateKey: privateKey).hexToBytes()
        }
        return nil
    }
    
    private class func checksum(datas: [UInt8]) -> [UInt8] {
        return datas + CryptoFx.sha256(input: CryptoFx.sha256(input: datas)).prefix(4)
    }
    
    public class func secp256k1Address(privKey: [UInt8]) -> [UInt8] {
        let publicKey = Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: true)
        return CryptoFx.ripemd160(input: CryptoFx.sha256(input: publicKey.hexToBytes()))
    }
    
    public class func p2pkhAddress(privKey: [UInt8], hrp: String, compressed: Bool = false) -> String? {
        let publicKey = Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: compressed)
        return p2pkhAddress(pubKey: publicKey.hexToBytes(), hrp: hrp)
    }
    
    public class func p2pkhAddress(pubKey: [UInt8], hrp: String) -> String? {
        let ripesha = [0] + CryptoFx.ripemd160(input: CryptoFx.sha256(input: pubKey))
        let checksum = checksum(datas: ripesha)
        print(checksum.toHexString())
        return Base58Encoder.encode(checksum)
    }
    
    public class func bech32Address(privKey: [UInt8], hrp: String) -> String? {
        let ripesha = secp256k1Address(privKey: privKey)
        return bech32Address(ripesha: ripesha, hrp: hrp)
    }
    
    public class func bech32Address(ripesha: [UInt8], hrp: String) -> String? {
        let bech32 = SegwitAddrCoder()
        if let recoded = try? bech32.encode(hrp: hrp, program: Data(ripesha)) {
            return recoded
        }
        return nil
    }
    
    private class func fingerprintFromPrivKey(privKey: [UInt8]) -> [UInt8] {
        return Data(secp256k1Address(privKey: privKey)).prefix(4).bytes
    }
    
    private class func derivePath(key: BIP32KeyPair, childNumber: Int) -> ([UInt8], [UInt8])? {
        var dat: [UInt8] = []
                
        guard let privKey = key.privateKey else { return nil }
        if childNumber >= Int(truncating: pow(2, 31) as NSNumber) {
            dat = [0] + privKey.prefix(32)
        } else {
            dat = Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: true).hexToBytes()
        }
        
        dat += byteArray(from: childNumber).suffix(4)
        
        if let chainCode = key.chainCode {
            
            if let hmac = HashMAC.getHMAC512(data: dat, key: chainCode) {
                let L = String(hmac.toHexString().prefix(64))
                let R = String(hmac.toHexString().suffix(64))
                                                                
                if let childPrivateKey = HexUtil.modulo(a: HexUtil.addHex(a: L.hexToBytes(), b: privKey), b: SECP256k1_ORD.hexToBytes()) {
                    
                    let childChainCode = R.hexToBytes()
                    return (childPrivateKey, childChainCode)
                }
            }
        }
        
        return nil
    }

    private class func byteArray<T>(from value: T) -> [UInt8] where T: FixedWidthInteger {
        withUnsafeBytes(of: value.bigEndian, Array.init)
    }
    
    private class func testPath(path:String) -> Bool {
        let range = NSRange(location: 0, length: path.utf8.count)
        let regex = try! NSRegularExpression(pattern: "m/[0-9'/]+$")
        return regex.firstMatch(in: path, options: [], range: range) != nil
    }
    
}
