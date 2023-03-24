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
import EIP_712
import BigInteger

public class Web3Crypto {
    
    static let shared = Web3Crypto()

    private let SECP256k1_ORD = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
    
    let bech32 = SegwitAddrCoder()

    public func getBip32Key(seed: Seed) -> BIP32KeyPair {
        let binarySeed = Mnemonic.toBinarySeed(mnemonicPhrase: seed)
        return BIP32KeyPair(fromSeed: binarySeed)
    }
    
    public func getBip32Key(binarySeed: [UInt8]) -> BIP32KeyPair {
        return BIP32KeyPair(fromSeed: binarySeed)
    }
    
    public func getFingerprint(seed: Seed) -> [UInt8]? {
        let keyPair = getBip32Key(seed: seed)
        
        if let privKey = keyPair.privateKey {
            return fingerprintParentKey(privKey: privKey)
        }
        
        return nil
    }
    
    public func Account(path: String, key: BIP32KeyPair) -> Web3Account? {
        if let extendedPrivateKey = deriveExtKey(path: path, key: key) {
            let privKey = Array(extendedPrivateKey[46...77])
            let pubKey = PublicKey(privKey: privKey)
            let address = Address(privateKey: privKey)
            
            return Web3Account.init(address: "0x" + address,
                                    publicKey: "0x" + pubKey,
                                    privateKey: "0x" + privKey.toHexString())
        }
        return nil
    }
    
    
    public func PublicKey(privKey: String, compressed: Bool = false) -> String {
        PublicKey(privKey: privKey.hexToBytes(), compressed: compressed)
    }
    
    public func PublicKey(privKey: [UInt8], compressed: Bool = false) -> String {
        Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: compressed)
    }
    
    public func Address(publicKey: String) -> String {
        Web3Util.Key.getAddressFromPublicKey(publicKey: publicKey.hexToBytes())
    }
    
    public func Address(privateKey: String) -> String {
        Address(privateKey: privateKey.hexToBytes())
    }
    
    public func Address(privateKey: [UInt8]) -> String {
        Web3Util.Key.getAddressFromPrivateKey(privKey: privateKey)
    }
    
    public func derivePublicKey(xPub: String, index: Int) -> [UInt8]? {
        let path = "m/\(index)"
        let key = Base58Encoder.decode(xPub)
        let publicKey:[UInt8] = Array(key[45...77])
        let chainCode:[UInt8] = Array(key[13...44])
        let depth: Int = Int(Array(key[4...5]).first ?? 0)

        let xPub = BIP32KeyPair.init(privateKey: nil, chainCode: chainCode, publicKey: publicKey)
        return deriveExtKey(path: path, key: xPub, depth: depth, xPub: true)
    }
    
    public func deriveExtKey(xPrv: String, index: Int, xPub: Bool = false) -> [UInt8]? {
        let path = "m/\(index)"
        let key = Base58Encoder.decode(xPrv)
        let privKey:[UInt8] = Array(key[46...77])
        let chainCode:[UInt8] = Array(key[13...44])
        let depth: Int = Int(Array(key[4...5]).first ?? 0)

        let xPriv = BIP32KeyPair.init(privateKey: privKey, chainCode: chainCode, publicKey: nil)
        return deriveExtKey(path: path, key: xPriv, depth: depth, xPub: xPub)
    }
    
    public func deriveExtKey(path: String, key: BIP32KeyPair, depth: Int = 0, xPub: Bool = false) -> [UInt8]? {
        
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

        let isPublicParent = key.privateKey == nil

        guard let masterChainCode = key.chainCode else { return nil }

        var depth = depth
        var parentFingerprint:[UInt8] = []
        var childNumber = 0
        var privateKey = isPublicParent ? key.publicKey : key.privateKey!
        var publicKey : [UInt8] = []
        var chainCode = masterChainCode
        
        for item in pathNumbers {
            depth += 1
            
            childNumber = item
            parentFingerprint = fingerprintParentKey(privKey: privateKey, isPublicKey: isPublicParent)
             
            if isPublicParent {
                if let (privKey, derivedChainCode) = derivePubPath(xPub: privateKey, chainCode: chainCode, childNumber: childNumber) {
                    privateKey = privKey
                    publicKey = Web3Util.Key.getPublicFromPrivateKey(privKey: privateKey, compressed: true).hexToBytes()
                    chainCode = derivedChainCode
                } else {
                    return nil
                }
            } else {
                let key = BIP32KeyPair.init(privateKey: privateKey, chainCode: chainCode, publicKey: nil)

                if let (privKey, derivedChainCode) = derivePath(key: key, childNumber: childNumber) {
                    privateKey = privKey
                    publicKey = Web3Util.Key.getPublicFromPrivateKey(privKey: privateKey, compressed: true).hexToBytes()
                    chainCode = derivedChainCode
                } else {
                    return nil
                }
            }
            

        }
        
        let keyBytes:[UInt8] = xPub
        ? publicKey
        : [0] + privateKey
        let depthKey = byteArray(from: depth).suffix(1)
        let childNumberBytes = byteArray(from: childNumber).suffix(4)
        
        let versionBytes = xPub
        ? VersionBytes.mainnetPublic.rawValue.hexToBytes()
        : VersionBytes.mainnetPrivate.rawValue.hexToBytes()
        
        let allParts:[UInt8] = versionBytes + depthKey + parentFingerprint + childNumberBytes + chainCode + keyBytes
        
        return checksum(datas: allParts)
    }
    
    public func deriveAddress(path: String, key: BIP32KeyPair) -> [UInt8]? {
        if let extendedPrivateKey = deriveExtKey(path: path, key: key) {
            let privateKey:[UInt8] = Array(extendedPrivateKey[46...77])
            return Address(privateKey: privateKey).hexToBytes()
        }
        return nil
    }
    
    public func deriveAddress(xPriv: Web3ExtPrivateKey, index: Int) -> [UInt8]? {
        if let extendedPrivateKey = deriveExtKey(xPrv: xPriv, index: index) {
            let privateKey:[UInt8] = Array(extendedPrivateKey[46...77])
            return Address(privateKey: privateKey).hexToBytes()
        }
        return nil
    }
    
    public func encodeTyped(messageJson: String) -> Data? {
        do {
            guard let data = messageJson.data(using: .utf8) else { return nil }
            return try JSONDecoder().decode(EIP712TypedData.self, from: data).signHash
        } catch {
            return nil
        }
    }
    
    public func checksum(datas: [UInt8]) -> [UInt8] {
        return datas + CryptoFx.sha256(input: CryptoFx.sha256(input: datas)).prefix(4)
    }
    
    public func cb58Checksum(data: [UInt8]) -> [UInt8] {
        return data + CryptoUtil.shared.sha256(input: data).suffix(4)
    }
    
    public func validateChecksum(datas: [UInt8]) -> [UInt8]? {
        guard datas.count > 4 else { return nil }
        let data = Data(datas.prefix(datas.count - 4)).bytes
        return datas == cb58Checksum(data: data) ? data : nil
    }
    
    public func secp256k1Address(privKey: [UInt8]) -> [UInt8] {
        let publicKey = Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: true)
        return CryptoFx.ripemd160(input: CryptoFx.sha256(input: publicKey.hexToBytes()))
    }
    
    public func getBigUInt(val: Any) -> BigUInt? {
        return val as? BigUInt
    }
    
    public func p2pkhAddress(privKey: [UInt8], hrp: String, compressed: Bool = false) -> String? {
        let publicKey = Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: compressed)
        return p2pkhAddress(pubKey: publicKey.hexToBytes(), hrp: hrp)
    }
    
    public func p2pshAddress(privKey: [UInt8], hrp: String, compressed: Bool = false) -> String? {
        let publicKey = Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: compressed)
        return p2pshAddress(pubKey: publicKey.hexToBytes(), hrp: hrp)
    }
    
    public func p2pshAddress(pubKey: [UInt8], hrp: String) -> String? {
        let script_sig = "0014".hexToBytes() + CryptoFx.ripemd160(input: CryptoFx.sha256(input: pubKey))
        let ripesha = "05".hexToBytes() + CryptoFx.ripemd160(input: CryptoFx.sha256(input: script_sig))
        return Base58Encoder.encode(checksum(datas: ripesha))
    }
    
    public func p2pkhAddress(pubKey: [UInt8], hrp: String) -> String? {
        let ripesha = [0] + CryptoFx.ripemd160(input: CryptoFx.sha256(input: pubKey))
        let checksum = checksum(datas: ripesha)
        return Base58Encoder.encode(checksum)
    }
    
    public func validateMnemonic(seed: Seed) -> Bool {
        return true
    }
    
    public func bech32Address(privKey: [UInt8], hrp: String) -> String? {
        let ripesha = secp256k1Address(privKey: privKey)
        return bech32Address(ripesha: ripesha, hrp: hrp)
    }
    
    public func bech32Address(ripesha: [UInt8], hrp: String) -> String? {
        return try? bech32.encode(hrp: hrp, program: Data(ripesha))
    }
    
    public func encodeSegwit(hrp: String, addr: String) -> [UInt8]? {
        return try? bech32.decode(hrp: hrp, addr: addr).program.bytes
    }
    
    private func fingerprintParentKey(privKey: [UInt8], isPublicKey: Bool = false) -> [UInt8] {
        if !isPublicKey {
            return Data(secp256k1Address(privKey: privKey)).prefix(4).bytes
        } else {
            return Data(CryptoFx.ripemd160(input: CryptoFx.sha256(input: privKey))).prefix(4).bytes
        }
    }
     
    public func derivePubPath(xPub: [UInt8], chainCode: [UInt8], childNumber: Int) -> ([UInt8], [UInt8])? {
        var dat: [UInt8] = xPub

        if childNumber >= Int(truncating: pow(2, 31) as NSNumber) {
            return nil
        }
          
        dat += byteArray(from: childNumber).suffix(4)
        
        if let hmac = HashMAC.getHMAC512(data: dat, key: chainCode),
            let L = BigUInt(String(hmac.toHexString().prefix(64)), radix: 16) {
            let R = String(hmac.toHexString().suffix(64))
            
            //let publicKey = Web3Util.Key.getPublicFromPrivateKey(privKey: li, compressed: false).hexToBytes()

            //let childPub = HexUtil.addHex(a: li, b: xPub)
            return (L.serialize().bytes, R.hexToBytes())
        }
        
        return nil
    }
    
    public func derivePath(key: BIP32KeyPair, childNumber: Int) -> ([UInt8], [UInt8])? {
        var dat: [UInt8] = []
                
        guard let privKey = key.privateKey else { return nil }
        if childNumber >= Int(truncating: pow(2, 31) as NSNumber) {
            dat = [0] + privKey.prefix(32)
        } else {
            dat = Web3Util.Key.getPublicFromPrivateKey(privKey: privKey, compressed: true).hexToBytes()
        }
        
        dat += byteArray(from: childNumber).suffix(4)
        
        if let chainCode = key.chainCode {
            
            if let hmac = HashMAC.getHMAC512(data: dat, key: chainCode),
                let privInt = BigUInt.init(privKey.toHexString(), radix: 16),
                let L = BigUInt(String(hmac.toHexString().prefix(64)), radix: 16),
                let secp256k1_ord = BigUInt.init(SECP256k1_ORD, radix: 16) {
                
                let R = String(hmac.toHexString().suffix(64))
                
                let childPriv = (L + privInt).quotientAndRemainder(dividingBy: secp256k1_ord).remainder.serialize().bytes
                                
                return (childPriv, R.hexToBytes())
            }
        }
        return nil
    }

    private func byteArray<T>(from value: T) -> [UInt8] where T: FixedWidthInteger {
        withUnsafeBytes(of: value.bigEndian, Array.init)
    }
    
    private func testPath(path:String) -> Bool {
        let range = NSRange(location: 0, length: path.utf8.count)
        let regex = try! NSRegularExpression(pattern: "m/[0-9'/]+$")
        return regex.firstMatch(in: path, options: [], range: range) != nil
    }
    
}
